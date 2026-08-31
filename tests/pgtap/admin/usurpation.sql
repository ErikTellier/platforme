-- PRENDRE LA PLACE D'UN UTILISATEUR, ET SOUS QUELLES CONDITIONS.
--
-- ═══ POURQUOI CE FICHIER EST LE PLUS IMPORTANT DU DOSSIER ═══
--
-- L'usurpation est la capacité la plus dangereuse du produit : un opérateur agit
-- DANS le compte d'un utilisateur final, et tout ce qu'il y fait porte la
-- signature de cet utilisateur. Les autres gardes protègent des données ; celle
-- -ci protège de l'attribution — « ce n'est pas moi qui ai fait ça » doit rester
-- vérifiable.
--
-- ═══ LE PLAFOND SUIT L'AUTORITÉ DÉTENUE, PAS L'ACTION DEMANDÉE ═══
--
-- `authority_scope.max_impersonation` déclare une heure pour la plateforme et
-- vingt minutes pour un client. La garde prend le plafond du périmètre le plus
-- large détenu VIVANT par l'opérateur — pas celui de l'action, pas une constante.
--
-- D'où le cœur de ce banc : LA MÊME DEMANDE, quarante-cinq minutes, passe pour
-- un administrateur de plateforme et se fait refuser pour un administrateur de
-- client. Un banc qui n'éprouverait qu'un seul opérateur laisserait croire à une
-- durée codée en dur, et ne verrait pas le jour où la politique change.
--
-- « Fermé par défaut » complète la règle : sans plafond trouvé, on refuse. Une
-- politique incomplète n'est pas une permission.
--
-- ═══ L'AUTORITÉ EST RELUE À L'ÉCRITURE, ENCORE ═══
--
-- `AD091` — « aucune autorité vivante sur ce client » — semble inatteignable :
-- signer la commande exige déjà cette autorité, via `may_operate` dans
-- `command_matches_presence`. Le seul chemin qui y mène est la RÉVOCATION QUI
-- TOMBE ENTRE LA TOUCHE ET L'ÉCRITURE, et c'est exactement le cas qui compte —
-- couper l'accès d'un opérateur doit mordre sur ce qu'il n'a pas encore fait.
--
-- C'est la troisième fois que ce motif apparaît dans ce dossier, après
-- `demande-autorite.sql` et `octroi-autorite.sql`. Ce n'est pas une coïncidence :
-- c'est la signature du schéma, qui ne fait jamais confiance à une vérification
-- passée.
--
-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
--   contrainte    impersonation_end_complete
--   contrainte    impersonation_ticket_not_blank
--   déclencheur   impersonation_guard
--   déclencheur   impersonation_end_only
--   déclencheur   impersonation_no_delete
--   index         uq_one_live_impersonation
--
-- `impersonation_expires_after_start` et `impersonation_ended_after_start`
-- survivent : ce banc n'écrit jamais de dates incohérentes, faute d'un cas
-- réaliste qui le ferait. Le compte de la base entière vit dans
-- `packages/harnais/mutation-sql.mjs`.
--
-- ═══ LE MONTAGE ═══
--
--   C  l'administrateur d'amorçage
--   A  un administrateur de PLATEFORME — plafond d'une heure
--   W  un administrateur d'un seul CLIENT — plafond de vingt minutes
--   T  le client visé, T2 un autre
--
-- W est posé par un octroi de portée client en règle : `TENANT` n'exige ni
-- demande approuvée ni second approbateur, donc la cérémonie tient en une ligne.

SET search_path TO pgtap, public;

SELECT plan(18);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

CREATE FUNCTION pg_temp.commande(
    p_user uuid, p_session uuid, p_key uuid, p_action text, p_graine text,
    p_scope text DEFAULT 'PLATFORM', p_tenant uuid DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE
    v_defi uuid := gen_random_uuid();
    v_cmd  uuid := gen_random_uuid();
BEGIN
    INSERT INTO webauthn.challenge
        (id, user_id, session_id, challenge, action, expires_at, scope,
         target_tenant_id, consumed_at)
    VALUES (v_defi, p_user, p_session, decode(repeat(p_graine, 4), 'hex'),
            p_action, now() + interval '5 minutes', p_scope, p_tenant, now());

    INSERT INTO admin.signed_command
        (id, user_id, session_id, key_id, challenge_id, action, scope,
         target_tenant_id, command_digest, issued_at)
    VALUES (v_cmd, p_user, p_session, p_key, v_defi, p_action, p_scope,
            p_tenant, decode(repeat(p_graine, 32), 'hex'), now());

    RETURN v_cmd;
END;
$f$;

CREATE FUNCTION pg_temp.poste(p_user uuid, p_session uuid, p_key uuid)
RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
    -- UNE HEURE, ET PAS DEUX. `session_ceiling_bounded` plafonne la durée de
    -- vie absolue d'une session : c'est `an_hour_is_an_hour`, et le banc s'y
    -- plie comme n'importe quel appelant.
    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES (p_session, p_user, now() + interval '1 hour');

    INSERT INTO akeys.key
        (id, kid, user_id, session_id, public_jwk, kms_ref,
         activated_at, signs_until, published_until, purpose, state)
    VALUES (p_key, gen_random_uuid(), p_user, p_session,
            '{"kty":"EC"}'::jsonb, 'kms://banc',
            now(), now() + interval '1 hour', now() + interval '2 hours',
            'COMMAND', 'ACTIVE');
END;
$f$;

DO $$
DECLARE
    c  uuid := (SELECT user_id FROM admin.platform_admin WHERE revoked_at IS NULL LIMIT 1);
    a  uuid := gen_random_uuid();
    w  uuid := gen_random_uuid();
    t  uuid := gen_random_uuid();
    t2 uuid := gen_random_uuid();
    sc uuid := gen_random_uuid();
    sa uuid := gen_random_uuid();
    sw uuid := gen_random_uuid();
    kc uuid := gen_random_uuid();
    ka uuid := gen_random_uuid();
    kw uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (a), (w);
    PERFORM pg_temp.poste(c, sc, kc);

    -- A : administrateur de plateforme, par bris de glace comme le premier.
    INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, break_glass, command_id)
    VALUES (a, c, 'Administrateur de plateforme du banc', true,
            pg_temp.commande(c, sc, kc, 'authority.grant', '60'));

    PERFORM pg_temp.poste(a, sa, ka);

    -- W : administrateur d'un seul client. La portée TENANT n'exige ni demande
    -- approuvée ni second approbateur — la cérémonie tient en une ligne.
    INSERT INTO admin.admin_tenant
        (user_id, tenant_id, granted_by, reason, command_id)
    VALUES (w, t, a, 'Exploitation du client',
            pg_temp.commande(a, sa, ka, 'authority.grant', '61', 'TENANT', t));

    PERFORM pg_temp.poste(w, sw, kw);

    PERFORM set_config('essai.a', a::text, false);
    PERFORM set_config('essai.w', w::text, false);
    PERFORM set_config('essai.c', c::text, false);
    PERFORM set_config('essai.t', t::text, false);
    PERFORM set_config('essai.t2', t2::text, false);

    PERFORM set_config('essai.i_a',
        pg_temp.commande(a, sa, ka, 'tenant.impersonate', '62', 'TENANT', t)::text, false);
    PERFORM set_config('essai.i_a2',
        pg_temp.commande(a, sa, ka, 'tenant.impersonate', '63', 'TENANT', t)::text, false);
    PERFORM set_config('essai.i_a3',
        pg_temp.commande(a, sa, ka, 'tenant.impersonate', '68', 'TENANT', t)::text, false);
    PERFORM set_config('essai.i_w',
        pg_temp.commande(w, sw, kw, 'tenant.impersonate', '64', 'TENANT', t)::text, false);
    PERFORM set_config('essai.i_w2',
        pg_temp.commande(w, sw, kw, 'tenant.impersonate', '65', 'TENANT', t)::text, false);
    PERFORM set_config('essai.i_w3',
        pg_temp.commande(w, sw, kw, 'tenant.impersonate', '69', 'TENANT', t)::text, false);
    -- Une action réelle du vocabulaire, mais pas une usurpation.
    PERFORM set_config('essai.autre',
        pg_temp.commande(a, sa, ka, 'tenant.suspend', '66', 'TENANT', t)::text, false);
    -- Une usurpation, mais d'un AUTRE client.
    PERFORM set_config('essai.i_t2',
        pg_temp.commande(a, sa, ka, 'tenant.impersonate', '67', 'TENANT', t2)::text, false);
    PERFORM set_config('essai.v_a',
        pg_temp.commande(a, sa, ka, 'authority.revoke', '6a', 'TENANT', t)::text, false);
END $$;

SELECT isnt(
    nullif(current_setting('essai.w', true), ''),
    NULL,
    'the platform admin and the tenant-scoped admin both exist'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE PLAFOND SUIT LA PERSONNE
--
--  QUARANTE-CINQ MINUTES, DEMANDÉES DEUX FOIS. Acceptées pour A, refusées pour
--  W. C'est la même durée, la même action, le même client : seule change
--  l'autorité détenue, et c'est tout le propos.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.impersonation
        (id, command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, started_at, expires_at)
      VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              current_setting('essai.i_a')::uuid,
              current_setting('essai.a')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1042', 'reproduction du defaut',
              now(), now() + interval '45 minutes')$$,
    'a platform admin may impersonate for 45 minutes'
);

SELECT throws_ok(
    $$INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, started_at, expires_at)
      VALUES (current_setting('essai.i_w')::uuid,
              current_setting('essai.w')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1043', 'reproduction du defaut',
              now(), now() + interval '45 minutes')$$,
    'AD092', NULL,
    'the very same 45 minutes are refused to a tenant-scoped admin'
);

SELECT lives_ok(
    $$INSERT INTO admin.impersonation
        (id, command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, started_at, expires_at)
      VALUES ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
              current_setting('essai.i_w')::uuid,
              current_setting('essai.w')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1043', 'reproduction du defaut',
              now(), now() + interval '15 minutes')$$,
    'within their own twenty-minute ceiling, the tenant admin may impersonate'
);

-- Et le plafond de la plateforme n'est pas infini pour autant.
SELECT throws_ok(
    $$INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, started_at, expires_at)
      VALUES (current_setting('essai.i_a2')::uuid,
              current_setting('essai.a')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1044', 'longue investigation',
              now(), now() + interval '90 minutes')$$,
    'AD092', NULL,
    'even a platform admin is capped, at one hour'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA PRÉSENCE PROUVÉE DOIT ÊTRE CELLE-CI
--
--  Trois égalités : l'action, le client, l'opérateur. Sans elles, une touche
--  donnée pour « suspendre un client » ouvrirait une session dans le compte
--  d'un de ses utilisateurs.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, expires_at)
      VALUES (current_setting('essai.autre')::uuid,
              current_setting('essai.a')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1045', 'motif',
              now() + interval '10 minutes')$$,
    'AD090', NULL,
    'a presence proved for another action does not open a session'
);

SELECT throws_ok(
    $$INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, expires_at)
      VALUES (current_setting('essai.i_t2')::uuid,
              current_setting('essai.a')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1046', 'motif',
              now() + interval '10 minutes')$$,
    'AD090', NULL,
    'a presence proved for another tenant does not open this one'
);

SELECT throws_ok(
    $$INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, expires_at)
      VALUES (current_setting('essai.i_a3')::uuid,
              current_setting('essai.w')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1047', 'motif',
              now() + interval '10 minutes')$$,
    'AD090', NULL,
    'one operator''s presence does not open a session for another'
);

-- UNE PRÉSENCE, UNE USURPATION. Rejouer la commande rouvrirait une session sur
-- une preuve déjà dépensée.
SELECT throws_ok(
    $$INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, expires_at)
      VALUES (current_setting('essai.i_a')::uuid,
              current_setting('essai.a')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1048', 'motif',
              now() + interval '10 minutes')$$,
    '23505', NULL,
    'a proof of presence opens one impersonation, never two'
);

-- UNE SEULE SESSION VIVANTE PAR OPÉRATEUR. Deux comptes ouverts en même temps,
-- et « qui a fait quoi » cesse de se répondre.
SELECT throws_ok(
    $$INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, expires_at)
      VALUES (current_setting('essai.i_a2')::uuid,
              current_setting('essai.a')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1049', 'motif',
              now() + interval '10 minutes')$$,
    '23505', NULL,
    'one operator holds at most one live impersonation'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA FORME
-- ═══════════════════════════════════════════════════════════════════════════

-- LE BILLET N'EST PAS DÉCORATIF. « Pourquoi as-tu ouvert le compte de ce client
-- le 3 mars » est la question posée en revue, et un motif libre sans référence
-- externe n'y répond pas. Une chaîne d'espaces non plus.
SELECT throws_ok(
    $$INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, expires_at)
      VALUES (current_setting('essai.i_a2')::uuid,
              current_setting('essai.a')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), '   ', 'motif',
              now() + interval '10 minutes')$$,
    '23514', NULL,
    'a ticket made of spaces is not a ticket'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  L'AUTORITÉ RETIRÉE ENTRE LA TOUCHE ET L'ÉCRITURE
-- ═══════════════════════════════════════════════════════════════════════════

DO $$
BEGIN
    UPDATE admin.admin_tenant
       SET revoked_at = now(),
           revoked_by = current_setting('essai.a')::uuid,
           revoked_command_id = current_setting('essai.v_a')::uuid
     WHERE user_id = current_setting('essai.w')::uuid;
END $$;

SELECT throws_ok(
    $$INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, expires_at)
      VALUES (current_setting('essai.i_w2')::uuid,
              current_setting('essai.w')::uuid,
              current_setting('essai.t')::uuid,
              gen_random_uuid(), 'INC-1050', 'motif',
              now() + interval '10 minutes')$$,
    'AD091', NULL,
    'an operator whose authority was just revoked opens nothing more'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE USURPATION EST UN FAIT : SEULE SA FIN S'ÉCRIT
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$UPDATE admin.impersonation
         SET ended_at = now(), end_reason = 'OPERATOR_CLOSED'
       WHERE id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'an impersonation is closed by dating its end'
);

SELECT throws_ok(
    $$UPDATE admin.impersonation
         SET ended_at = now(), end_reason = 'ENCORE'
       WHERE id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'AD093', NULL,
    'an impersonation already ended does not end again'
);

SELECT throws_ok(
    $$UPDATE admin.impersonation
         SET ended_at = now(), end_reason = 'CLOS',
             ticket_ref = 'INC-9999'
       WHERE id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'$$,
    'AD093', NULL,
    'the ticket cannot be rewritten while closing the session it justified'
);

-- UNE FIN SANS MOTIF. La date seule ne dit pas si la session a été fermée par
-- l'opérateur, par l'échéance, ou par un incident.
SELECT throws_ok(
    $$UPDATE admin.impersonation SET ended_at = now()
       WHERE id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'$$,
    '23514', NULL,
    'an end without a reason is refused'
);

SELECT throws_ok(
    $$DELETE FROM admin.impersonation
       WHERE id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'AD071', NULL,
    'an impersonation is never deleted'
);

SELECT is(
    (SELECT count(*)::int FROM admin.impersonation
      WHERE id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        AND ticket_ref = 'INC-1042'
        AND end_reason = 'OPERATOR_CLOSED'),
    1,
    'the closed impersonation is still there, with the ticket that justified it'
);

SELECT * FROM finish();
