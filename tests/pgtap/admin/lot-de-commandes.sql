-- UNE TOUCHE, PLUSIEURS COMMANDES — ET RIEN DE PLUS.
--
-- ═══ CE QU'UN LOT RÉSOUT, ET CE QU'IL POURRAIT ROUVRIR ═══
--
-- Demander une touche matérielle par commande est intenable dès qu'un geste en
-- comporte dix. Le lot permet d'en signer plusieurs d'un coup — et rouvre du
-- même mouvement le trou que la preuve de présence avait fermé, si rien ne
-- borne ce qu'une seule touche autorise.
--
-- DEUX ENGAGEMENTS, ET IL EN FAUT DEUX :
--
--   manifest_digest   engage CE QUI était prévu
--   declared_count    engage COMBIEN
--
-- Sans le second, un lot s'étendrait après la touche : la somme du manifeste
-- reste vraie pour les commandes qu'elle couvre, et rien n'empêcherait d'en
-- ajouter une onzième. Le schéma le dit dans son propre message d'erreur, et
-- deux assertions ci-dessous le tiennent en place.
--
-- ═══ ET LE PÉRIMÈTRE NE SE NÉGOCIE PAS EN COURS DE ROUTE ═══
--
-- `command_belongs_to_its_batch` exige quatre égalités entre la commande et son
-- lot : même opérateur, même session, même portée, même client. Sans elles, une
-- touche donnée pour un client autoriserait une écriture chez un autre — très
-- exactement ce que le lot est censé ne pas rouvrir.
--
-- ═══ UNE PREUVE, UNE SEULE FORME ═══
--
-- Une commande porte SOIT un défi, SOIT un lot. `signed_command_one_proof` le
-- dit, et `commande-signee.sql` l'éprouve déjà. Les commandes de ce fichier
-- n'ont donc aucun `challenge_id` : leur preuve, c'est le lot.
--
-- ═══ LE MONTAGE ═══
--
--   C   l'administrateur d'amorçage, une session, une clé
--   T   un client, pour éprouver le périmètre
--   Un lot de DEUX commandes déclarées, et une session voisine pour les cas
--   où l'appartenance doit être refusée.

SET search_path TO pgtap, public;

SELECT plan(18);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

CREATE FUNCTION pg_temp.defi(
    p_user uuid, p_session uuid, p_action text, p_graine text,
    p_scope text DEFAULT 'PLATFORM', p_tenant uuid DEFAULT NULL,
    p_consomme boolean DEFAULT true
) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
    v_defi uuid := gen_random_uuid();
BEGIN
    INSERT INTO webauthn.challenge
        (id, user_id, session_id, challenge, action, expires_at, scope,
         target_tenant_id, consumed_at)
    VALUES (v_defi, p_user, p_session, decode(repeat(p_graine, 4), 'hex'),
            p_action, now() + interval '5 minutes', p_scope, p_tenant,
            CASE WHEN p_consomme THEN now() END);

    RETURN v_defi;
END;
$f$;

DO $$
DECLARE
    c  uuid := (SELECT user_id FROM admin.platform_admin WHERE revoked_at IS NULL LIMIT 1);
    t  uuid := gen_random_uuid();
    sc uuid := '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    kc uuid := '0502aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
BEGIN
    PERFORM set_config('app.caller', 'banc-du-lot', false);

    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES (sc, c, now() + interval '1 hour');

    INSERT INTO akeys.key
        (id, kid, user_id, session_id, public_jwk, kms_ref,
         activated_at, signs_until, published_until, purpose, state)
    VALUES (kc, gen_random_uuid(), c, sc, '{"kty":"EC"}'::jsonb, 'kms://banc',
            now(), now() + interval '1 hour', now() + interval '2 hours',
            'COMMAND', 'ACTIVE');

    PERFORM set_config('essai.c', c::text, false);
    PERFORM set_config('essai.t', t::text, false);

    -- Les défis. Chacun ne sert qu'une fois : `uq_batch_challenge`.
    PERFORM set_config('essai.b1', pg_temp.defi(c, sc, 'batch.sign', '10')::text, false);
    PERFORM set_config('essai.b2', pg_temp.defi(c, sc, 'batch.sign', '11')::text, false);
    PERFORM set_config('essai.b3', pg_temp.defi(c, sc, 'batch.sign', '12')::text, false);
    PERFORM set_config('essai.b4', pg_temp.defi(c, sc, 'batch.sign', '13')::text, false);
    -- Posé mais jamais prouvé.
    PERFORM set_config('essai.nu',
        pg_temp.defi(c, sc, 'batch.sign', '14', 'PLATFORM', NULL, false)::text, false);
    -- Une présence prouvée pour autre chose qu'un lot.
    PERFORM set_config('essai.autre',
        pg_temp.defi(c, sc, 'authority.request', '15')::text, false);
    -- Un lot prouvé pour un CLIENT, là où on en voudra un de plateforme.
    PERFORM set_config('essai.client',
        pg_temp.defi(c, sc, 'batch.sign', '16', 'TENANT', t)::text, false);
END $$;

SELECT isnt(
    nullif(current_setting('essai.c', true), ''),
    NULL,
    'the operator, the session and the key of this bench exist'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  OUVRIR UN LOT
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.command_batch
        (id, user_id, session_id, challenge_id, scope, manifest_digest,
         declared_count)
      VALUES ('0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.b1')::uuid,
              'PLATFORM', decode(repeat('a1', 32), 'hex'), 2)$$,
    'a batch of two declared commands is opened'
);

-- UN DÉFI POSÉ N'EST PAS UN DÉFI PROUVÉ. Sans cette porte, ouvrir un lot
-- reviendrait à demander une touche puis à l'ignorer.
SELECT throws_ok(
    $$INSERT INTO admin.command_batch
        (user_id, session_id, challenge_id, scope, manifest_digest, declared_count)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.nu')::uuid,
              'PLATFORM', decode(repeat('a2', 32), 'hex'), 2)$$,
    'AD110', NULL,
    'a batch opened on a challenge nobody touched is refused'
);

-- UNE PRÉSENCE PROUVÉE POUR AUTRE CHOSE. Récolter une touche pour un geste
-- anodin et la dépenser en lot est exactement le détournement à fermer.
SELECT throws_ok(
    $$INSERT INTO admin.command_batch
        (user_id, session_id, challenge_id, scope, manifest_digest, declared_count)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.autre')::uuid,
              'PLATFORM', decode(repeat('a3', 32), 'hex'), 2)$$,
    'AD110', NULL,
    'nor one opened on a presence proved for another kind of act'
);

-- NI SUR UN AUTRE PÉRIMÈTRE. La touche vaut pour le client qu'elle nommait.
SELECT throws_ok(
    $$INSERT INTO admin.command_batch
        (user_id, session_id, challenge_id, scope, manifest_digest, declared_count)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.client')::uuid,
              'PLATFORM', decode(repeat('a4', 32), 'hex'), 2)$$,
    'AD110', NULL,
    'nor on a presence proved for a different perimeter'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA FORME DU MANIFESTE
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$INSERT INTO admin.command_batch
        (user_id, session_id, challenge_id, scope, manifest_digest, declared_count)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.b2')::uuid,
              'PLATFORM', decode('a5a5', 'hex'), 2)$$,
    '23514', NULL,
    'a manifest digest shorter than 32 bytes is not a SHA-256'
);

-- UN LOT DE ZÉRO COMMANDE. Il n'engage rien, et sa somme couvre le vide : la
-- première commande écrite serait alors la onzième d'un lot sans plafond.
SELECT throws_ok(
    $$INSERT INTO admin.command_batch
        (user_id, session_id, challenge_id, scope, manifest_digest, declared_count)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.b2')::uuid,
              'PLATFORM', decode(repeat('a6', 32), 'hex'), 0)$$,
    '23514', NULL,
    'a batch that declares no command declares nothing'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  DEUX UNICITÉS
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$INSERT INTO admin.command_batch
        (user_id, session_id, challenge_id, scope, manifest_digest, declared_count)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.b1')::uuid,
              'PLATFORM', decode(repeat('a7', 32), 'hex'), 2)$$,
    '23505', NULL,
    'one touch opens one batch, never two'
);

SELECT throws_ok(
    $$INSERT INTO admin.command_batch
        (user_id, session_id, challenge_id, scope, manifest_digest, declared_count)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.b2')::uuid,
              'PLATFORM', decode(repeat('a1', 32), 'hex'), 2)$$,
    '23505', NULL,
    'and the same manifest is never replayed under a second touch'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UN LOT EST UN FAIT
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE admin.command_batch SET declared_count = 99
       WHERE id = '0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'AD083', NULL,
    'the count a batch declared cannot be raised after the touch'
);

SELECT throws_ok(
    $$DELETE FROM admin.command_batch
       WHERE id = '0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'AD083', NULL,
    'and a batch is never deleted'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LES COMMANDES DU LOT
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.signed_command
        (user_id, session_id, key_id, batch_id, batch_seq, action, scope,
         command_digest, issued_at)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0502aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 1,
              'authority.request', 'PLATFORM',
              decode(repeat('b1', 32), 'hex'), now())$$,
    'the first command of the batch is written'
);

-- LE PÉRIMÈTRE DU LOT VAUT POUR CHACUNE. Une commande visant un client alors
-- que le lot était de plateforme rouvrirait tout le trou.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (user_id, session_id, key_id, batch_id, batch_seq, action, scope,
         target_tenant_id, command_digest, issued_at)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0502aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 2,
              'authority.request', 'TENANT',
              current_setting('essai.t')::uuid,
              decode(repeat('b2', 32), 'hex'), now())$$,
    'AD111', NULL,
    'a command may not name a batch signed for another perimeter'
);

-- DEUX COMMANDES AU MÊME RANG. Le rang est ce qui les relie au manifeste : deux
-- au même numéro, et on ne sait plus laquelle il couvrait.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (user_id, session_id, key_id, batch_id, batch_seq, action, scope,
         command_digest, issued_at)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0502aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 1,
              'authority.request', 'PLATFORM',
              decode(repeat('b3', 32), 'hex'), now())$$,
    '23505', NULL,
    'two commands may not share a rank in the same batch'
);

-- UN RANG AU-DELÀ DU COMPTE. La somme du manifeste reste vraie pour ce qu'elle
-- couvre ; c'est le COMPTE qui empêche d'écrire au-delà.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (user_id, session_id, key_id, batch_id, batch_seq, action, scope,
         command_digest, issued_at)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0502aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 3,
              'authority.request', 'PLATFORM',
              decode(repeat('b4', 32), 'hex'), now())$$,
    'AD112', NULL,
    'a rank beyond what the manifest declared is refused'
);

SELECT lives_ok(
    $$INSERT INTO admin.signed_command
        (user_id, session_id, key_id, batch_id, batch_seq, action, scope,
         command_digest, issued_at)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0502aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 2,
              'authority.request', 'PLATFORM',
              decode(repeat('b5', 32), 'hex'), now())$$,
    'the last declared command still passes — the boundary is inclusive'
);

-- ET LA SUIVANTE, NON. Le lot est plein : sans ce refus, une touche pour deux
-- commandes en autoriserait autant qu'on veut.
SELECT throws_ok(
    $$INSERT INTO admin.signed_command
        (user_id, session_id, key_id, batch_id, batch_seq, action, scope,
         command_digest, issued_at)
      VALUES (current_setting('essai.c')::uuid,
              '0501aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0502aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 1,
              'authority.request', 'PLATFORM',
              decode(repeat('b6', 32), 'hex'), now())$$,
    'AD112', NULL,
    'and a full batch takes no more, however low the rank asked for'
);

SELECT is(
    (SELECT count(*)::int FROM admin.signed_command
      WHERE batch_id = '0503aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    2,
    'so one touch signed exactly the two commands it committed to'
);

SELECT * FROM finish();
