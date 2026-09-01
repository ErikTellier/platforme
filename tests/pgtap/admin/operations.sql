-- LES GESTES D'EXPLOITATION, ET CE QU'ILS REFUSENT DE FAIRE.
--
-- ═══ NEUF FONCTIONS, ET AUCUN BANC NE LES APPELAIT ═══
--
-- Le schéma expose des fonctions qui FONT quelque chose : déclarer un
-- administrateur, en révoquer un, noter une assertion WebAuthn, fermer les
-- sessions périmées, purger. Les contraintes et les déclencheurs autour d'elles
-- sont éprouvés depuis longtemps ; elles, non — et une fonction n'est atteinte
-- que par un banc qui l'appelle.
--
-- ═══ `AD004` : ON NE SE VERROUILLE PAS DEHORS ═══
--
-- La plus importante du fichier. `revoke_admin` refuse de révoquer LE DERNIER
-- administrateur de plateforme vivant.
--
-- Sans ce refus, un geste de nettoyage — révoquer un compte qui part — laisse
-- une base où plus personne ne peut rien accorder : il n'y a plus d'autorité
-- pour signer l'octroi qui en recréerait une. La seule sortie serait une
-- migration de genèse, c'est-à-dire un accès direct à la production.
--
-- ═══ LA GENÈSE EST UNE MIGRATION, PAS UNE ROUTE ═══
--
-- `user_is_signed` laisse passer un compte sans parrain : c'est ce qui permet
-- d'amorcer. `provision_admin` REFUSE cette forme — une fonction qui
-- transmettrait des nuls ouvrirait la porte de la genèse au plan applicatif,
-- et n'importe qui pourrait se déclarer administrateur sans que personne ne le
-- signe.
--
-- Deux gardes pour le même invariant, à deux niveaux, et seule la seconde est
-- appelable depuis l'extérieur.

SET search_path TO pgtap, public;

SELECT plan(14);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

CREATE FUNCTION pg_temp.commande(
    p_user uuid, p_session uuid, p_key uuid, p_action text, p_graine text
) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
    v_defi uuid := gen_random_uuid();
    v_cmd  uuid := gen_random_uuid();
BEGIN
    INSERT INTO webauthn.challenge
        (id, user_id, session_id, challenge, action, expires_at, scope, consumed_at)
    VALUES (v_defi, p_user, p_session, decode(repeat(p_graine, 4), 'hex'),
            p_action, now() + interval '5 minutes', 'PLATFORM', now());

    INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope,
         command_digest, issued_at)
    VALUES (v_cmd, p_user, p_session, p_key, v_defi, p_action, 'PLATFORM',
            decode(repeat(p_graine, 32), 'hex'), now());

    RETURN v_cmd;
END;
$f$;

DO $$
DECLARE
    c uuid := (SELECT user_id FROM admin.platform_admin WHERE revoked_at IS NULL LIMIT 1);
    s uuid := '1001aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    k uuid := '1002aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
BEGIN
    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES (s, c, now() + interval '1 hour');

    INSERT INTO akeys.key
        (id, kid, user_id, session_id, public_jwk, kms_ref,
         activated_at, signs_until, published_until, purpose, state)
    VALUES (k, gen_random_uuid(), c, s, '{"kty":"EC"}'::jsonb, 'kms://banc',
            now(), now() + interval '1 hour', now() + interval '2 hours',
            'COMMAND', 'ACTIVE');

    PERFORM set_config('essai.c', c::text, false);
    PERFORM set_config('essai.p1',
        pg_temp.commande(c, s, k, 'identity.provision', '20')::text, false);
    PERFORM set_config('essai.g1',
        pg_temp.commande(c, s, k, 'authority.grant', '21')::text, false);
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.effective_authority WHERE scope = 'PLATFORM'),
    1,
    'exactly one platform administrator holds the base at this point'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  ON NE SE VERROUILLE PAS DEHORS
--
--  LA PLUS IMPORTANTE. Révoquer le dernier laisserait une base où plus personne
--  ne peut rien accorder — et où la seule sortie serait un accès direct à la
--  production.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$SELECT * FROM admin.revoke_admin(current_setting('essai.c')::uuid)$$,
    'AD004', NULL,
    'the last live platform admin may not be revoked'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  DÉCLARER UN ADMINISTRATEUR
-- ═══════════════════════════════════════════════════════════════════════════

-- LA GENÈSE N'EST PAS UNE ROUTE. Le déclencheur laisse passer un compte sans
-- parrain — il le faut, pour amorcer. La fonction, elle, refuse.
SELECT throws_ok(
    $$SELECT admin.provision_admin('ENTRA', 'neuf@banc', NULL,
                                   current_setting('essai.p1')::uuid)$$,
    'AD051', NULL,
    'provisioning without an author is refused by the function'
);

SELECT throws_ok(
    $$SELECT admin.provision_admin('ENTRA', 'neuf@banc',
                                   current_setting('essai.c')::uuid, NULL)$$,
    'AD051', NULL,
    'and so is provisioning without the command that proves it'
);

DO $$ BEGIN
  PERFORM set_config('essai.neuf',
    admin.provision_admin('ENTRA', 'neuf@banc',
                          current_setting('essai.c')::uuid,
                          current_setting('essai.p1')::uuid)::text, false);
END $$;

-- L'IDENTITÉ NAÎT LIÉE, et sans `provision_key` : l'annuaire rend l'identifiant
-- opaque tout de suite, donc l'adresse de connexion n'est jamais écrite, même
-- temporairement.
SELECT is(
    (SELECT count(*)::int FROM admin.identity
      WHERE user_id = current_setting('essai.neuf')::uuid
        AND provider_id = 'neuf@banc'
        AND provision_key IS NULL
        AND bound_at IS NOT NULL),
    1,
    'provisioning creates the account and its bound identity in one act'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  RÉVOQUER, UNE FOIS QU'IL EN RESTE UN AUTRE
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  INSERT INTO admin.platform_admin (user_id, granted_by, reason, break_glass, command_id)
  VALUES (current_setting('essai.neuf')::uuid, current_setting('essai.c')::uuid,
          'Second administrateur du banc', true, current_setting('essai.g1')::uuid);

  INSERT INTO admin.session (id, user_id, absolute_expires_at)
  VALUES ('1003aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          current_setting('essai.neuf')::uuid, now() + interval '1 hour');
END $$;

SELECT is(
    (SELECT sessions_closed FROM admin.revoke_admin(
        current_setting('essai.neuf')::uuid)),
    1,
    'revoking an administrator closes their live session in the same act'
);

SELECT is(
    (SELECT deactivated_at IS NOT NULL FROM admin."user"
      WHERE id = current_setting('essai.neuf')::uuid),
    true,
    'and deactivates the account, not merely the authority'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE COMPTEUR D'UN AUTHENTIFICATEUR
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  INSERT INTO webauthn.authenticator
      (id, user_id, credential_id, public_key, sign_count)
  VALUES ('1004aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          current_setting('essai.c')::uuid, '\xfeed'::bytea, '\x01'::bytea, 5);
END $$;

SELECT is(
    (SELECT count(*)::int FROM webauthn.note_assertion(
        current_setting('essai.c')::uuid, '\xfeed'::bytea, 6)),
    1,
    'noting an assertion moves the counter forward'
);

-- ET LE GARDE MORD À TRAVERS LA FONCTION. Elle n'écrit pas en contournant : la
-- régression est refusée là aussi.
SELECT throws_ok(
    $$SELECT * FROM webauthn.note_assertion(
        current_setting('essai.c')::uuid, '\xfeed'::bytea, 6)$$,
    'AD031', NULL,
    'while a counter that does not move is refused through the function too'
);

DO $$ BEGIN
  PERFORM webauthn.revoke_authenticator('1004aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
END $$;

SELECT is(
    (SELECT count(*)::int FROM webauthn.note_assertion(
        current_setting('essai.c')::uuid, '\xfeed'::bytea, 9)),
    0,
    'and a revoked authenticator notes nothing at all'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  FERMER CE QUI A EXPIRÉ
--
--  Un délai d'attente s'applique à une session dont la présence n'a jamais été
--  prouvée — personne n'a fini de se connecter. Dès qu'une paire existe, la
--  session vit sa vie et ce délai n'a plus rien à dire.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$
DECLARE
    a uuid := gen_random_uuid();
    b uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (a), (b);

    -- Ouverte il y a longtemps, jamais prouvee.
    INSERT INTO admin.session (id, user_id, created_at, absolute_expires_at)
    VALUES ('1005aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', a,
            now() - interval '30 minutes', now() + interval '30 minutes');

    -- Aussi ancienne, mais avec une paire vivante.
    INSERT INTO admin.session (id, user_id, created_at, absolute_expires_at)
    VALUES ('1006aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', b,
            now() - interval '30 minutes', now() + interval '30 minutes');

    INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
    VALUES ('1006aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            gen_random_uuid(), gen_random_uuid(), now() + interval '15 minutes');

    PERFORM admin.expire_sessions();
END $$;

SELECT is(
    (SELECT end_reason FROM admin.session
      WHERE id = '1005aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    'EXPIRED',
    'a session nobody ever proved dies once its grace has run out'
);

SELECT is(
    (SELECT count(*)::int FROM admin.session
      WHERE id = '1006aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' AND ended_at IS NULL),
    1,
    'while one that carries a live pair lives on, however old'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  PURGER LES DÉFIS
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  INSERT INTO webauthn.challenge
      (user_id, session_id, challenge, action, created_at, expires_at, scope, consumed_at)
  VALUES (current_setting('essai.c')::uuid,
          '1001aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '\xbeef01'::bytea,
          'authority.request', now() - interval '10 days',
          now() - interval '10 days' + interval '5 minutes', 'PLATFORM', now() - interval '10 days');

  INSERT INTO webauthn.challenge
      (user_id, session_id, challenge, action, created_at, expires_at, scope)
  VALUES (current_setting('essai.c')::uuid,
          '1001aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '\xbeef02'::bytea,
          'authority.request', now() - interval '10 days',
          now() + interval '5 minutes', 'PLATFORM');

  PERFORM webauthn.purge_challenges();
END $$;

SELECT is(
    (SELECT count(*)::int FROM webauthn.challenge WHERE challenge = '\xbeef01'::bytea),
    0,
    'an old, spent challenge is purged'
);

SELECT is(
    (SELECT count(*)::int FROM webauthn.challenge WHERE challenge = '\xbeef02'::bytea),
    1,
    'but an old one still awaiting its touch is not'
);

SELECT * FROM finish();
