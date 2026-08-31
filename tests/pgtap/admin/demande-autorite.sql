-- LE FLUX À QUATRE YEUX, ÉPROUVÉ.
--
-- ═══ L'INVARIANT QUE CE FICHIER DÉFEND ═══
--
-- Personne ne se donne l'autorité. Trois personnes distinctes interviennent :
-- celui qui DEMANDE, celui qui la RECEVRA, et un TIERS qui approuve — et ce
-- tiers doit déjà détenir l'autorité sur ce périmètre, sinon un second regard
-- serait celui de n'importe qui.
--
-- C'est la règle la plus facile à contourner par accident, parce qu'il suffit
-- d'une colonne qu'on remplit soi-même pour que « quatre yeux » redevienne
-- deux. Les assertions ci-dessous essaient chacun de ces contournements.
--
-- ═══ CE QUE LES DÉCLENCHEURS OMBRAGENT ═══
--
-- Les déclencheurs `BEFORE` s'exécutent AVANT les `CHECK` et les clés
-- étrangères. `request_is_signed` compare la demande à la commande qui la
-- signe : périmètre, client visé, auteur. Toute ligne qui s'écarte de sa
-- commande reçoit donc `AD088` avant que le `CHECK` correspondant n'ait la
-- parole.
--
-- Ces bancs affirment le code RÉELLEMENT rendu. C'est celui que le code
-- applicatif traitera, et l'affirmation reste vraie si l'ordre des gardes
-- change un jour.
--
-- ═══ L'ORDRE DES DÉCLENCHEURS EST ALPHABÉTIQUE, ET ON S'EN SERT ═══
--
--   authority_request_is_a_fact       AD089  ce qui est écrit ne se réécrit pas
--   authority_request_is_signed       AD088  la ligne correspond à sa commande
--   zz_request_expiry_is_binding      AD094  une échéance passée est passée
--
-- Le `zz_` n'est pas décoratif : l'échéance ne se juge qu'une fois la ligne
-- reconnue conforme. Renommer changerait l'ordre, donc le code rendu, donc ces
-- bancs — c'est voulu, ils le tiennent en place.
--
-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
-- `pnpm mutation:sql admin` retire chaque objet du schéma à son tour et
-- redemande le banc. Sept meurent grâce à ce fichier :
--
--   contrainte    authority_request_approver_is_a_third
--   contrainte    authority_request_not_for_oneself
--   contrainte    authority_request_one_outcome
--   déclencheur   authority_request_is_a_fact
--   déclencheur   authority_request_is_signed
--   déclencheur   authority_request_no_delete
--   déclencheur   zz_request_expiry_is_binding
--
-- Le compte de la base entière vit dans `packages/harnais/mutation-sql.mjs`,
-- qui explique aussi pourquoi les politiques `owner_is_the_vetted_path`
-- meurent sans qu'aucune assertion ne les nomme.

-- ═══ LE MONTAGE ═══
--
--   C  l'administrateur d'amorçage, qui approuve
--   A  un SECOND administrateur, qui demande — puis à qui on retire l'autorité
--   B  le sujet, simple utilisateur : celui pour qui on demande
--
-- A doit être administrateur, et ce n'est pas une commodité : `may_operate()`
-- est relu à chaque commande signée, donc un demandeur sans autorité ne peut
-- pas produire la commande qui porte sa demande. Une demande d'autorité est
-- faite PAR quelqu'un en place POUR un nouveau venu ; c'est `not_for_oneself`
-- qui l'empêche d'étendre la sienne.
--
-- `pg_temp.commande()` fabrique un défi consommé PUIS la commande signée qui
-- s'y adosse : `signed_command_matches_presence` exige que les deux concordent,
-- et l'écrire six fois à la main serait six occasions de se tromper. Le schéma
-- temporaire disparaît avec la transaction, que le lanceur annule de toute
-- façon.

SET search_path TO pgtap, public;

SELECT plan(18);

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

CREATE FUNCTION pg_temp.poste(p_user uuid, p_session uuid, p_key uuid)
RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
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
    b  uuid := gen_random_uuid();
    sc uuid := gen_random_uuid();
    sa uuid := gen_random_uuid();
    kc uuid := gen_random_uuid();
    ka uuid := gen_random_uuid();
    cmd_grant uuid;
BEGIN
    -- Utilisateurs « genèse » : sans parrain, donc sans commande de
    -- provisionnement. `user_is_signed` laisse passer ce cas, et lui seul.
    INSERT INTO admin."user" (id) VALUES (a), (b);

    PERFORM pg_temp.poste(c, sc, kc);

    -- ═══ POURQUOI A DOIT ÊTRE ADMINISTRATEUR ═══
    --
    -- `command_matches_presence` relit `may_operate()` à CHAQUE commande : on ne
    -- signe rien sur un périmètre où l'on n'a pas déjà l'autorité. Un demandeur
    -- sans autorité ne peut donc pas produire la commande qui porte sa demande.
    --
    -- Ce n'est pas une gêne du banc, c'est le modèle : une demande d'autorité
    -- est faite PAR un administrateur en place POUR un nouveau venu. C'est
    -- `not_for_oneself` qui empêche d'étendre la sienne.
    --
    -- On pose donc A par BRIS DE GLACE — exactement comme la migration a posé
    -- l'administrateur d'amorçage, et pour la même raison : il n'y a pas de
    -- second approbateur avant qu'il y ait deux administrateurs.
    cmd_grant := pg_temp.commande(c, sc, kc, 'authority.grant', '60');

    INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, break_glass, command_id)
    VALUES (a, c, 'Second administrateur du banc', true, cmd_grant);

    PERFORM pg_temp.poste(a, sa, ka);

    PERFORM set_config('essai.c', c::text, false);
    PERFORM set_config('essai.a', a::text, false);
    PERFORM set_config('essai.b', b::text, false);

    -- Une commande par usage : `uq_command_challenge` et `uq_command_digest`
    -- interdisent d'en recycler une.
    PERFORM set_config('essai.req_a',
        pg_temp.commande(a, sa, ka, 'authority.request',  '61')::text, false);
    PERFORM set_config('essai.req_a2',
        pg_temp.commande(a, sa, ka, 'authority.request',  '62')::text, false);
    PERFORM set_config('essai.req_c',
        pg_temp.commande(c, sc, kc, 'authority.request',  '63')::text, false);
    PERFORM set_config('essai.app_c',
        pg_temp.commande(c, sc, kc, 'authority.approve',  '64')::text, false);
    PERFORM set_config('essai.app_a',
        pg_temp.commande(a, sa, ka, 'authority.approve',  '65')::text, false);
    PERFORM set_config('essai.wdr_a',
        pg_temp.commande(a, sa, ka, 'authority.withdraw', '66')::text, false);

    -- ═══ ET MAINTENANT ON LUI RETIRE L'AUTORITÉ ═══
    --
    -- A a signé ses commandes pendant qu'il l'avait ; il ne l'a plus. C'est
    -- l'état exact que le dernier cas du banc éprouve, et il vient EN DERNIER
    -- pour ne pas gêner les commandes déjà émises — une commande passée reste
    -- valide, c'est son emploi futur qui ne l'est plus.
    UPDATE admin.platform_admin
       SET revoked_at = now(),
           revoked_by = c,
           revoked_command_id = pg_temp.commande(c, sc, kc, 'authority.revoke', '67')
     WHERE user_id = a;
END $$;

SELECT isnt(
    nullif(current_setting('essai.c', true), ''),
    NULL,
    'the bootstrap admin holds the authority every approval below leans on'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LES DEUX CAS QUI DOIVENT PASSER
--
--  Un banc qui n'affirme que des refus passe au vert quand la table refuse
--  TOUT. Ces deux-là sont ce qui empêche les quinze autres de se féliciter
--  d'un montage cassé.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.authority_request
        (id, scope, subject_user_id, reason, requested_by, request_command_id)
      VALUES ('99999999-9999-4999-8999-999999999999', 'PLATFORM',
              current_setting('essai.b')::uuid, 'astreinte',
              current_setting('essai.a')::uuid,
              current_setting('essai.req_a')::uuid)$$,
    'a well-formed request is recorded'
);

SELECT lives_ok(
    $$UPDATE admin.authority_request
         SET approved_at = now(),
             approved_by = current_setting('essai.c')::uuid,
             approval_command_id = current_setting('essai.app_c')::uuid
       WHERE id = '99999999-9999-4999-8999-999999999999'$$,
    'a third party who already holds the authority may approve'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  TROIS PERSONNES, ET PAS DEUX
-- ═══════════════════════════════════════════════════════════════════════════

-- DEMANDER POUR SOI. La porte la plus évidente, et celle qu'on oublie : sans
-- elle, l'élévation ne demande qu'une seule signature — la sienne.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id)
      VALUES ('PLATFORM', current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.a')::uuid,
              current_setting('essai.req_a2')::uuid)$$,
    '23514', NULL,
    'nobody may request the authority for themselves'
);

-- APPROUVER SA PROPRE DEMANDE. Le demandeur détient ici l'autorité — c'est le
-- seul cas où `signs_here` ne masque pas la règle des trois personnes, et donc
-- le seul qui l'éprouve vraiment.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id,
         approved_at, approved_by, approval_command_id)
      VALUES ('PLATFORM', current_setting('essai.b')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.req_c')::uuid,
              now(), current_setting('essai.c')::uuid,
              current_setting('essai.app_c')::uuid)$$,
    '23514', NULL,
    'the one who asked may not be the one who approves'
);

-- APPROUVER SA PROPRE ÉLÉVATION. L'autre moitié de la même règle : le sujet est
-- ici l'administrateur d'amorçage, donc il détient l'autorité — et ça ne suffit
-- pas.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id,
         approved_at, approved_by, approval_command_id)
      VALUES ('PLATFORM', current_setting('essai.c')::uuid, 'astreinte',
              current_setting('essai.a')::uuid,
              current_setting('essai.req_a2')::uuid,
              now(), current_setting('essai.c')::uuid,
              current_setting('essai.app_c')::uuid)$$,
    '23514', NULL,
    'the one who receives the authority may not approve their own elevation'
);

-- L'AUTORITÉ RETIRÉE ENTRE LA SIGNATURE ET L'EMPLOI.
--
-- C'est le cas que seule une relecture À L'USAGE attrape. A détenait l'autorité
-- quand il a touché sa clé : sa commande d'approbation est authentique, et le
-- restera. Entre-temps elle lui a été retirée.
--
-- Une vérification faite au moment de SIGNER laisserait passer : elle a eu
-- lieu, et elle disait vrai. `request_is_signed` rappelle `signs_here` au
-- moment d'ÉCRIRE, et refuse.
--
-- C'est aussi, incidemment, le seul chemin par lequel un approbateur sans
-- autorité peut se présenter : sans autorité, on ne signe rien du tout — la
-- garde `may_operate` de `command_matches_presence` mord bien avant.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id,
         approved_at, approved_by, approval_command_id)
      VALUES ('PLATFORM', current_setting('essai.b')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.req_c')::uuid,
              now(), current_setting('essai.a')::uuid,
              current_setting('essai.app_a')::uuid)$$,
    'AD088', NULL,
    'authority revoked between signing and using is refused at the moment of use'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CHAQUE GESTE EST ADOSSÉ À SA PROPRE SIGNATURE
--
--  C'EST LE CŒUR. Si l'approbation pouvait citer la commande d'un autre, la
--  seconde paire d'yeux redeviendrait une colonne que quelqu'un remplit.
-- ═══════════════════════════════════════════════════════════════════════════

-- La demande cite la commande de quelqu'un d'autre.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id)
      VALUES ('PLATFORM', current_setting('essai.b')::uuid, 'astreinte',
              current_setting('essai.a')::uuid,
              current_setting('essai.req_c')::uuid)$$,
    'AD088', NULL,
    'a request may not lean on somebody else''s command'
);

-- L'approbation cite la commande de quelqu'un d'autre — celle du demandeur.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id,
         approved_at, approved_by, approval_command_id)
      VALUES ('PLATFORM', current_setting('essai.b')::uuid, 'astreinte',
              current_setting('essai.a')::uuid,
              current_setting('essai.req_a2')::uuid,
              now(), current_setting('essai.c')::uuid,
              current_setting('essai.app_a')::uuid)$$,
    'AD088', NULL,
    'an approval may not lean on somebody else''s command'
);

-- Une date d'approbation sans approbateur. `approval_complete` dit la même
-- chose, mais le déclencheur parle le premier : il cherche une commande signée
-- par un auteur nul, et n'en trouve pas.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id, approved_at)
      VALUES ('PLATFORM', current_setting('essai.b')::uuid, 'astreinte',
              current_setting('essai.a')::uuid,
              current_setting('essai.req_a2')::uuid, now())$$,
    'AD088', NULL,
    'an approval date without an approver is refused'
);

-- Le périmètre de la ligne doit être celui de la commande. Sans cette
-- comparaison, une touche donnée pour un client servirait pour un autre.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, tenant_id, subject_user_id, reason, requested_by, request_command_id)
      VALUES ('PLATFORM', gen_random_uuid(), current_setting('essai.b')::uuid,
              'astreinte', current_setting('essai.a')::uuid,
              current_setting('essai.req_a2')::uuid)$$,
    'AD088', NULL,
    'a request whose perimeter differs from its command is refused'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE DEMANDE EST UN FAIT
--
--  Approuver autre chose que ce qui a été demandé est exactement la façon dont
--  un second regard cesse de vouloir dire quelque chose.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE admin.authority_request
         SET subject_user_id = current_setting('essai.a')::uuid
       WHERE id = '99999999-9999-4999-8999-999999999999'$$,
    'AD089', NULL,
    'the subject of a request cannot be changed after the fact'
);

-- Et une fois dénouée, la ligne ne bouge plus. Le montage l'a approuvée plus
-- haut : elle est donc déjà réglée.
SELECT throws_ok(
    $$UPDATE admin.authority_request
         SET withdrawn_at = now(),
             withdrawn_by = current_setting('essai.a')::uuid,
             withdrawal_command_id = current_setting('essai.wdr_a')::uuid
       WHERE id = '99999999-9999-4999-8999-999999999999'$$,
    'AD089', NULL,
    'a request that is already settled cannot be settled again'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UNE ÉCHÉANCE QUE PERSONNE N'APPLIQUE N'EST PAS UNE ÉCHÉANCE
-- ═══════════════════════════════════════════════════════════════════════════

INSERT INTO admin.authority_request
    (id, scope, subject_user_id, reason, requested_by, request_command_id, expires_at)
VALUES ('88888888-8888-4888-8888-888888888888', 'PLATFORM',
        current_setting('essai.b')::uuid, 'astreinte courte',
        current_setting('essai.a')::uuid,
        current_setting('essai.req_a2')::uuid,
        now() - interval '1 minute');

SELECT throws_ok(
    $$UPDATE admin.authority_request
         SET approved_at = now(),
             approved_by = current_setting('essai.c')::uuid,
             approval_command_id = current_setting('essai.app_c')::uuid
       WHERE id = '88888888-8888-4888-8888-888888888888'$$,
    'AD094', NULL,
    'a request whose deadline has passed can no longer be approved'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  UN DÉNOUEMENT, UN SEUL
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id,
         approved_at, approved_by, approval_command_id,
         withdrawn_at, withdrawn_by, withdrawal_command_id)
      VALUES ('PLATFORM', current_setting('essai.b')::uuid, 'astreinte',
              current_setting('essai.a')::uuid,
              current_setting('essai.req_a')::uuid,
              now(), current_setting('essai.c')::uuid,
              current_setting('essai.app_c')::uuid,
              now(), current_setting('essai.a')::uuid,
              current_setting('essai.wdr_a')::uuid)$$,
    '23514', NULL,
    'a request cannot be both approved and withdrawn'
);

-- Une date de retrait sans auteur. Ici le déclencheur se tait — il exige les
-- DEUX pour se prononcer — et le `CHECK` a donc la parole.
SELECT throws_ok(
    $$INSERT INTO admin.authority_request
        (scope, subject_user_id, reason, requested_by, request_command_id, withdrawn_at)
      VALUES ('PLATFORM', current_setting('essai.b')::uuid, 'astreinte',
              current_setting('essai.a')::uuid,
              current_setting('essai.req_a2')::uuid, now())$$,
    '23514', NULL,
    'a withdrawal date without an author is refused'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  RIEN NE S'EFFACE
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$DELETE FROM admin.authority_request
       WHERE id = '99999999-9999-4999-8999-999999999999'$$,
    'AD040', NULL,
    'a request cannot be deleted'
);

SELECT is(
    (SELECT count(*)::int FROM admin.authority_request
      WHERE id = '99999999-9999-4999-8999-999999999999'),
    1,
    'the approved request is still there after every attempt above'
);

SELECT * FROM finish();
