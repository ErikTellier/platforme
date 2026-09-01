-- RETIRER UNE DEMANDE, LA TROISIÈME ISSUE.
--
-- ═══ CE QUE `demande-autorite.sql` NE COUVRAIT PAS ═══
--
-- Une demande d'autorité a trois fins possibles : elle est APPROUVÉE, elle est
-- RETIRÉE, ou elle reste en attente. Le premier chemin est éprouvé de bout en
-- bout ; le deuxième ne l'était pas du tout, alors que c'est celui qu'on
-- emprunte quand on s'est trompé — donc dans la précipitation.
--
-- ═══ LE RETRAIT SE SIGNE COMME LE RESTE ═══
--
-- `request_is_signed` exige, pour un retrait, la même chose que pour une
-- approbation : une commande `authority.withdraw`, sur le même périmètre, ET
-- SIGNÉE PAR CELUI QUI RETIRE. Retirer annule une autorité que quelqu'un
-- allait détenir — ce n'est pas moins un acte que de l'accorder.
--
-- UNE RÉSERVE ASSUMÉE PAR LE SCHÉMA, et il faut la dire : on ne vérifie PAS que
-- l'auteur du retrait est le demandeur. La migration
-- `a_withdrawal_is_signed_like_the_rest` le note explicitement — la règle n'est
-- pas tranchée. Ce banc éprouve donc ce qui EST décidé, et ne prête pas au
-- schéma une intention qu'il n'a pas.
--
-- ═══ DEUX CONTRAINTES QUI SE RECOUVRENT, ET COMMENT LES SÉPARER ═══
--
--   withdrawal_complete    (withdrawn_at IS NULL) = (withdrawn_by IS NULL)
--   withdrawal_is_signed   (withdrawn_at IS NULL) = (withdrawal_command_id IS NULL)
--
-- Une date seule viole LES DEUX : en retirer une laisse l'autre, et le refus
-- reste. C'est pour ça qu'elles survivaient toutes deux à un banc qui ne
-- testait que ce cas-là. Chaque assertion ci-dessous n'en viole qu'UNE, sans
-- quoi elle n'affirmerait rien sur celle qu'elle nomme.

SET search_path TO pgtap, public;

SELECT plan(11);

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
    c  uuid := (SELECT user_id FROM admin.platform_admin WHERE revoked_at IS NULL LIMIT 1);
    s  uuid := '0601aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    k  uuid := '0602aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    b  uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (b);

    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES (s, c, now() + interval '1 hour');

    INSERT INTO akeys.key
        (id, kid, user_id, session_id, public_jwk, kms_ref,
         activated_at, signs_until, published_until, purpose, state)
    VALUES (k, gen_random_uuid(), c, s, '{"kty":"EC"}'::jsonb, 'kms://banc',
            now(), now() + interval '1 hour', now() + interval '2 hours',
            'COMMAND', 'ACTIVE');

    PERFORM set_config('essai.c', c::text, false);
    PERFORM set_config('essai.b', b::text, false);

    FOR i IN 1..4 LOOP
        PERFORM set_config('essai.r' || i,
            pg_temp.commande(c, s, k, 'authority.request',
                             lpad(to_hex(32 + i), 2, '0'))::text, false);
    END LOOP;

    PERFORM set_config('essai.w1',
        pg_temp.commande(c, s, k, 'authority.withdraw', '40')::text, false);
    PERFORM set_config('essai.w2',
        pg_temp.commande(c, s, k, 'authority.withdraw', '41')::text, false);
    PERFORM set_config('essai.a1',
        pg_temp.commande(c, s, k, 'authority.approve', '42')::text, false);

    -- La demande qu'on retirera en règle.
    INSERT INTO admin.authority_request
        (id, scope, subject_user_id, reason, requested_by, request_command_id)
    VALUES ('0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'PLATFORM', b,
            'erreur de saisie', c, current_setting('essai.r1')::uuid);
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.authority_request
      WHERE id = '0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        AND approved_at IS NULL AND withdrawn_at IS NULL),
    1,
    'the request to be withdrawn is still pending'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  SÉPARER DEUX CONTRAINTES QUI SE RECOUVRENT
-- ═══════════════════════════════════════════════════════════════════════════

-- UNE DATE ET UNE COMMANDE, SANS AUTEUR. `withdrawal_is_signed` est satisfaite
-- — la date va avec la commande — donc seule `withdrawal_complete` parle.
--
-- Le déclencheur se tait ici : il exige la date ET l'auteur pour se prononcer,
-- et laisse volontairement la contrainte dire mieux la même chose.
SELECT throws_ok(
    $$UPDATE admin.authority_request
         SET withdrawn_at = now(),
             withdrawal_command_id = current_setting('essai.w1')::uuid
       WHERE id = '0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    '23514', NULL,
    'a withdrawal that names no author is refused'
);

-- ET UNE DATE ET UN AUTEUR, SANS COMMANDE. Cette fois `withdrawal_complete`
-- est satisfaite, mais le DÉCLENCHEUR se prononce avant la contrainte
-- jumelle : il cherche une commande nulle et n'en trouve pas.
SELECT throws_ok(
    $$UPDATE admin.authority_request
         SET withdrawn_at = now(),
             withdrawn_by = current_setting('essai.c')::uuid
       WHERE id = '0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'AD088', NULL,
    'and one that leans on no signed command is refused by the guard first'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE RETRAIT SE SIGNE
-- ═══════════════════════════════════════════════════════════════════════════

-- UNE COMMANDE QUI N'EST PAS UN RETRAIT. Une touche donnée pour approuver ne
-- doit pas servir à retirer : ce sont deux décisions opposées.
SELECT throws_ok(
    $$UPDATE admin.authority_request
         SET withdrawn_at = now(),
             withdrawn_by = current_setting('essai.c')::uuid,
             withdrawal_command_id = current_setting('essai.a1')::uuid
       WHERE id = '0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'AD088', NULL,
    'an approval command does not withdraw — they are opposite decisions'
);

SELECT lives_ok(
    $$UPDATE admin.authority_request
         SET withdrawn_at = now(),
             withdrawn_by = current_setting('essai.c')::uuid,
             withdrawal_command_id = current_setting('essai.w1')::uuid
       WHERE id = '0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'a pending request is withdrawn by a signed command'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE DEMANDE RETIRÉE EST DÉNOUÉE
--
--  Le même `AD089` que pour une demande approuvée : les deux issues ferment la
--  ligne, et rien ne distingue l'une de l'autre de ce point de vue.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE admin.authority_request
         SET approved_at = now(),
             approved_by = current_setting('essai.c')::uuid,
             approval_command_id = current_setting('essai.a1')::uuid
       WHERE id = '0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'AD089', NULL,
    'a withdrawn request can no longer be approved'
);

SELECT throws_ok(
    $$UPDATE admin.authority_request
         SET withdrawn_at = now(),
             withdrawn_by = current_setting('essai.c')::uuid,
             withdrawal_command_id = current_setting('essai.w2')::uuid
       WHERE id = '0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'AD089', NULL,
    'nor withdrawn a second time'
);

-- ET LE MOTIF DE LA DEMANDE SURVIT. C'est ce qu'on relira pour comprendre
-- pourquoi elle avait été ouverte, puis abandonnée.
SELECT is(
    (SELECT reason FROM admin.authority_request
      WHERE id = '0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    'erreur de saisie',
    'while the reason it was ever opened stays readable'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  DEUX AUTRES SÉPARATIONS
-- ═══════════════════════════════════════════════════════════════════════════

-- UN APPROBATEUR ET SA COMMANDE, SANS DATE. `request_is_signed` ne se prononce
-- que si `approved_at` est posée : il se tait, et `approval_complete` parle
-- seule. C'est la seule façon de l'atteindre.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id,
         approved_by, approval_command_id)
      VALUES ('PLATFORM', current_setting('essai.b')::uuid, 'sans date',
              current_setting('essai.c')::uuid,
              current_setting('essai.r2')::uuid,
              current_setting('essai.c')::uuid,
              current_setting('essai.a1')::uuid)$$,
    '23514', NULL,
    'an approver and their command, with no date, approve nothing'
);

-- UN SUJET QUI N'EXISTE PAS. Le déclencheur ne regarde PAS le sujet — il
-- compare la portée, le client et le demandeur — donc la clé étrangère reste
-- seule à garder cette porte.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id)
      VALUES ('PLATFORM', gen_random_uuid(), 'sujet inconnu',
              current_setting('essai.c')::uuid,
              current_setting('essai.r3')::uuid)$$,
    '23503', NULL,
    'a request cannot name a subject who does not exist'
);

SELECT throws_ok(
    $$DELETE FROM admin.authority_request
       WHERE id = '0603aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'$$,
    'AD040', NULL,
    'and a settled request is never deleted'
);

SELECT * FROM finish();
