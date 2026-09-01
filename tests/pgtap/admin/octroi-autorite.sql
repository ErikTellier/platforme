-- L'OCTROI DE L'AUTORITÉ, ÉPROUVÉ SUR SES DEUX PORTÉES.
--
-- ═══ LE MAILLON QUE CE FICHIER FERME ═══
--
-- `demande-autorite.sql` prouve qu'une demande ne s'approuve pas toute seule.
-- Il ne prouve pas que l'autorité RÉELLEMENT accordée est celle qui a été
-- approuvée. C'est ici, et c'est le maillon où le second regard se perd le plus
-- discrètement : approuver « trois jours pour B » puis écrire « sans terme pour
-- D » laisse deux signatures authentiques sur un octroi que personne n'a voulu.
--
-- ═══ UNE SEULE FAMILLE DE GARDES, DEUX POLITIQUES ═══
--
-- `platform_admin` et `admin_tenant` partagent leurs six déclencheurs : les
-- mêmes fonctions, paramétrées par `TG_ARGV`. Ce qui diffère tient dans une
-- ligne d'`admin.authority_scope` :
--
--              requires_second_approver   allows_break_glass
--   PLATFORM             oui                     oui
--   TENANT               non                     non
--
-- D'où deux comportements opposés, et c'est le contraste qui vaut d'être testé :
-- un octroi de plateforme SANS demande approuvée est refusé (`AD086`), un octroi
-- de client sans demande est la voie normale ; un bris de glace est ouvert à la
-- plateforme, et fermé au client (`AD076`).
--
-- Tester une seule des deux portées laisserait croire que la garde est
-- inconditionnelle, alors qu'elle lit une politique — et une politique se
-- modifie par un `UPDATE`.
--
-- ═══ L'ORDRE DES DÉCLENCHEURS, ENCORE ALPHABÉTIQUE ═══
--
--   <table>_grant_guard             AD070 AD074 AD075 AD076   la forme
--   <table>_is_signed               AD084 AD085               la signature
--   <table>_signer_has_authority    AD079                     le signataire
--   zzz_<table>_follows_a_request   AD086 AD087               la concordance
--
-- Le `zzz_` place la concordance EN DERNIER : inutile de comparer une ligne à
-- la demande qu'elle prétend suivre tant qu'on n'a pas établi qu'elle est bien
-- signée par quelqu'un qui pouvait signer.
--
-- ═══ CE QU'ON NE PEUT PAS ATTEINDRE, ET POURQUOI ═══
--
--   AD073   les deux portées déclarent `max_duration IS NULL`. La garde lit une
--           politique qui, aujourd'hui, ne plafonne rien. Poser un plafond dans
--           le banc testerait le banc, pas le schéma.
--   AD078   « aucune politique déclarée pour cette portée » suppose de vider
--           `authority_scope`, ce que la clé étrangère des demandes refuse.
--
-- Les deux survivront au mutant. C'est exact : rien ne les éprouve, faute de
-- données qui les rendent atteignables.
--
-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
-- Onze objets, sur les deux tables, et la répartition confirme le propos : les
-- gardes des deux portées meurent séparément, parce que les deux politiques
-- sont éprouvées.
--
--   déclencheur   platform_admin_grant_guard
--   déclencheur   platform_admin_is_signed
--   déclencheur   platform_admin_signer_has_authority
--   déclencheur   platform_admin_revocation_only
--   déclencheur   platform_admin_no_delete
--   déclencheur   zzz_platform_admin_follows_a_request
--   déclencheur   admin_tenant_grant_guard
--   déclencheur   admin_tenant_is_signed
--   déclencheur   admin_tenant_revocation_only
--   index         platform_admin_one_live
--   index         platform_admin_one_grant_per_request
--
-- Les `CHECK` de forme — `expires_after_granted`, `revoked_after_granted`,
-- `revocation_complete` — survivent : ce banc ne les éprouve pas. Le compte de
-- la base entière vit dans `packages/harnais/mutation-sql.mjs`.
--
-- ═══ LE MONTAGE ═══
--
--   C  l'administrateur d'amorçage, qui approuve et qui révoque
--   A  un second administrateur, qui demande et qui octroie
--   B  le sujet de l'octroi de plateforme
--   D  le sujet de l'octroi de client
--   E  un utilisateur désactivé
--   T  un client
--
-- Trois demandes sont posées d'avance : deux approuvées, une laissée en
-- attente. Les termes restent NULS des deux côtés — la concordance porte alors
-- sur `IS NOT DISTINCT FROM`, et le cas « terme différent » se teste en en
-- posant un d'un seul côté.

SET search_path TO pgtap, public;

SELECT plan(22);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

-- Même fabrique que dans `demande-autorite.sql`, ouverte aux deux portées :
-- `authority_is_signed('TENANT', …)` exige que la commande porte le client visé,
-- et pas seulement la bonne action.
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
    d  uuid := gen_random_uuid();
    e  uuid := gen_random_uuid();
    t  uuid := gen_random_uuid();
    sc uuid := gen_random_uuid();
    sa uuid := gen_random_uuid();
    kc uuid := gen_random_uuid();
    ka uuid := gen_random_uuid();
    r1 uuid := gen_random_uuid();
    r2 uuid := gen_random_uuid();
    r3 uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (a), (b), (d);
    INSERT INTO admin."user" (id, deactivated_at) VALUES (e, now());

    PERFORM pg_temp.poste(c, sc, kc);

    -- A devient administrateur par BRIS DE GLACE, comme la migration a posé le
    -- premier : `may_operate()` est relu à chaque commande signée, donc sans
    -- autorité A ne pourrait rien signer — ni demander, ni octroyer.
    INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, break_glass, command_id)
    VALUES (a, c, 'Second administrateur du banc', true,
            pg_temp.commande(c, sc, kc, 'authority.grant', '60'));

    PERFORM pg_temp.poste(a, sa, ka);

    PERFORM set_config('essai.c', c::text, false);
    PERFORM set_config('essai.a', a::text, false);
    PERFORM set_config('essai.b', b::text, false);
    PERFORM set_config('essai.d', d::text, false);
    PERFORM set_config('essai.e', e::text, false);
    PERFORM set_config('essai.t', t::text, false);
    PERFORM set_config('essai.r1', r1::text, false);
    PERFORM set_config('essai.r2', r2::text, false);
    PERFORM set_config('essai.r3', r3::text, false);

    -- UNE COMMANDE SERT PLUSIEURS ESSAIS REFUSÉS. Rien ne la consomme : c'est
    -- `uq_command_challenge` qui interdit d'en réutiliser une pour deux
    -- commandes, pas d'en citer une dans deux écritures dont l'une échoue.
    PERFORM set_config('essai.g_a',
        pg_temp.commande(a, sa, ka, 'authority.grant', '63')::text, false);
    PERFORM set_config('essai.gt_a',
        pg_temp.commande(a, sa, ka, 'authority.grant', '67', 'TENANT', t)::text, false);
    PERFORM set_config('essai.v_c',
        pg_temp.commande(c, sc, kc, 'authority.revoke', '69')::text, false);
    PERFORM set_config('essai.vt_c',
        pg_temp.commande(c, sc, kc, 'authority.revoke', '6a', 'TENANT', t)::text, false);

    -- TROIS DEMANDES : deux menées jusqu'à l'approbation, une laissée en
    -- attente pour éprouver `AD086` sur autre chose qu'un `request_id` nul.
    INSERT INTO admin.authority_request
        (id, scope, subject_user_id, reason, requested_by, request_command_id)
    VALUES (r1, 'PLATFORM', b, 'astreinte', a,
            pg_temp.commande(a, sa, ka, 'authority.request', '61')),
           (r2, 'PLATFORM', b, 'astreinte bis', a,
            pg_temp.commande(a, sa, ka, 'authority.request', '64')),
           (r3, 'PLATFORM', d, 'jamais approuvee', a,
            pg_temp.commande(a, sa, ka, 'authority.request', '66'));

    UPDATE admin.authority_request
       SET approved_at = now(), approved_by = c,
           approval_command_id = pg_temp.commande(c, sc, kc, 'authority.approve', '62')
     WHERE id = r1;

    UPDATE admin.authority_request
       SET approved_at = now(), approved_by = c,
           approval_command_id = pg_temp.commande(c, sc, kc, 'authority.approve', '65')
     WHERE id = r2;
END $$;

SELECT isnt(
    nullif(current_setting('essai.c', true), ''),
    NULL,
    'the bootstrap admin holds the authority the whole ceremony leans on'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA CÉRÉMONIE COMPLÈTE, DE BOUT EN BOUT
--
--  SANS CE CAS, LES DIX-NEUF REFUS NE VALENT RIEN. Une table qui refuse tout
--  les rendrait tous verts d'un coup.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.platform_admin
        (id, user_id, granted_by, reason, approved_by, command_id, request_id)
      VALUES ('77777777-7777-4777-8777-777777777777',
              current_setting('essai.b')::uuid,
              current_setting('essai.a')::uuid,
              'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r1')::uuid)$$,
    'a platform grant that follows an approved request is recorded'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  L'OCTROI DÉCRIT CE QUI A ÉTÉ APPROUVÉ
--
--  C'EST LE CŒUR DU FICHIER. Les deux signatures peuvent être authentiques et
--  l'octroi porter sur autre chose : c'est la seule façon dont quatre yeux
--  regardent une chose et une autre est écrite.
-- ═══════════════════════════════════════════════════════════════════════════

-- Aucune demande du tout.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id)
      VALUES (current_setting('essai.d')::uuid,
              current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid)$$,
    'AD086', NULL,
    'a platform grant without an approved request is refused'
);

-- Une demande qui existe, mais que personne n'a approuvée. Le cas que le simple
-- test « `request_id` est-il nul ? » laisserait passer.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id, request_id)
      VALUES (current_setting('essai.d')::uuid,
              current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r3')::uuid)$$,
    'AD086', NULL,
    'a grant leaning on a request nobody approved is refused'
);

-- APPROUVÉ POUR B, ÉCRIT POUR D. La substitution que tout le reste laisserait
-- passer : demande authentique, approbation authentique, bénéficiaire changé.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id, request_id)
      VALUES (current_setting('essai.d')::uuid,
              current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r2')::uuid)$$,
    'AD087', NULL,
    'a grant naming someone other than the approved subject is refused'
);

-- APPROUVÉ SANS TERME, ÉCRIT AVEC UN TERME — et l'inverse serait pire. Le terme
-- fait partie de ce qui a été regardé : approuver « trois jours » et accorder
-- dix ans ferait porter le second regard sur autre chose.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id, request_id, expires_at)
      VALUES (current_setting('essai.b')::uuid,
              current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r2')::uuid,
              now() + interval '10 years')$$,
    'AD087', NULL,
    'a grant whose term differs from the approved one is refused'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA FORME DE L'OCTROI
-- ═══════════════════════════════════════════════════════════════════════════

-- SANS SECOND APPROBATEUR. La garde lit `requires_second_approver` dans la
-- politique de la portée — d'où le cas TENANT plus bas, qui doit passer.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, command_id, request_id)
      VALUES (current_setting('essai.d')::uuid,
              current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r1')::uuid)$$,
    'AD075', NULL,
    'the platform scope refuses a grant with no second approver'
);

-- S'OCTROYER À SOI-MÊME. Distincte de `not_for_oneself` sur la demande : on
-- pourrait demander pour un autre et écrire pour soi.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id, request_id)
      VALUES (current_setting('essai.a')::uuid,
              current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r1')::uuid)$$,
    'AD074', NULL,
    'authority is never granted to oneself'
);

-- À UN COMPTE DÉSACTIVÉ. L'autorité dormirait, prête à se réveiller avec le
-- compte — et personne ne relit les octrois en réactivant un accès.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id, request_id)
      VALUES (current_setting('essai.e')::uuid,
              current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r1')::uuid)$$,
    'AD070', NULL,
    'authority is not granted to a deactivated account'
);

-- LA COMMANDE DÉPENSÉE N'EST PAS UN OCTROI PAR CELUI QUI OCTROIE. Ici elle est
-- signée par A, mais l'octroi se dit fait par C : un administrateur signe, un
-- autre se sert.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id, request_id)
      VALUES (current_setting('essai.d')::uuid,
              current_setting('essai.c')::uuid, 'astreinte',
              current_setting('essai.a')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r1')::uuid)$$,
    'AD085', NULL,
    'the command spent must be a grant by the one who grants'
);

-- DEUX AUTORITÉS VIVES POUR LA MÊME PERSONNE. La demande r2 est authentique et
-- approuvée ; B détient déjà l'autorité. Sans cet index, deux octrois
-- superposés donneraient deux révocations à faire, et on en oublierait une.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id, request_id)
      VALUES (current_setting('essai.b')::uuid,
              current_setting('essai.a')::uuid, 'astreinte bis',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r2')::uuid)$$,
    '23505', NULL,
    'one person holds at most one live platform authority'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA PORTÉE CLIENT, QUI SUIT UNE AUTRE POLITIQUE
--
--  Mêmes déclencheurs, mêmes fonctions, lecture différente : `TENANT` n'exige
--  pas de second approbateur et n'ouvre pas le bris de glace. Éprouver les deux
--  est ce qui distingue « la garde refuse » de « la garde lit la politique ».
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO admin.admin_tenant
        (id, user_id, tenant_id, granted_by, reason, command_id)
      VALUES ('66666666-6666-4666-8666-666666666666',
              current_setting('essai.d')::uuid,
              current_setting('essai.t')::uuid,
              current_setting('essai.a')::uuid,
              'exploitation',
              current_setting('essai.gt_a')::uuid)$$,
    'a tenant grant needs no request, and no second approver'
);

-- LE BRIS DE GLACE EST FERMÉ AU CLIENT. Il existe pour la plateforme, où il n'y
-- a parfois personne d'autre ; à l'échelle d'un client il y a toujours un
-- administrateur de plateforme pour faire le geste en règle.
SELECT throws_ok(
    $$INSERT INTO admin.admin_tenant
        (user_id, tenant_id, granted_by, reason, break_glass, command_id)
      VALUES (current_setting('essai.b')::uuid,
              current_setting('essai.t')::uuid,
              current_setting('essai.a')::uuid,
              'exploitation', true,
              current_setting('essai.gt_a')::uuid)$$,
    'AD076', NULL,
    'break-glass is not open to the tenant scope'
);

-- LA COMMANDE DOIT NOMMER LE MÊME CLIENT. Sans cette égalité, une touche donnée
-- pour un client ouvrirait l'accès à un autre.
SELECT throws_ok(
    $$INSERT INTO admin.admin_tenant
        (user_id, tenant_id, granted_by, reason, command_id)
      VALUES (current_setting('essai.b')::uuid,
              gen_random_uuid(),
              current_setting('essai.a')::uuid,
              'exploitation',
              current_setting('essai.gt_a')::uuid)$$,
    'AD085', NULL,
    'a tenant grant may not spend a command naming another tenant'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA RÉVOCATION
--
--  Une autorité ne s'efface pas, elle se date. Ce qui reste écrit est ce qui
--  rend l'octroi relisible un an plus tard.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$UPDATE admin.platform_admin
         SET revoked_at = now(),
             revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.v_c')::uuid
       WHERE id = '77777777-7777-4777-8777-777777777777'$$,
    'a platform authority is revoked by a signed command'
);

-- UNE APPROBATION NE SE DÉPENSE QU'UNE FOIS, MÊME APRÈS RÉVOCATION.
--
-- B n'a plus d'autorité vive : `one_live` ne s'y oppose plus, et tout le reste
-- concorde — même demande, même sujet, même octroyeur, même approbateur. Sans
-- l'index unique sur `request_id`, révoquer rendrait l'approbation réutilisable
-- et le second regard porterait sur un octroi déjà consommé.
--
-- CE CAS DOIT VENIR AVANT QUE A PERDE SON AUTORITÉ, plus bas : `AD079` le
-- devancerait, et le banc affirmerait alors autre chose que son intitulé.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id, request_id)
      VALUES (current_setting('essai.b')::uuid,
              current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r1')::uuid)$$,
    '23505', NULL,
    'an approval spent once cannot be spent again, even after a revocation'
);

-- REPOUSSER LE TERME. Le premier refus de la garde, et délibérément : rallonger
-- une autorité sans qu'aucune décision ne soit prise est ce qu'on ferait sans y
-- penser.
SELECT throws_ok(
    $$UPDATE admin.platform_admin
         SET expires_at = now() + interval '10 years'
       WHERE id = '77777777-7777-4777-8777-777777777777'$$,
    'AD077', NULL,
    'the term of a grant cannot be pushed back after the fact'
);

-- RÉVOQUER DEUX FOIS. La seconde écraserait la date de la première, donc la
-- trace de qui a fait quoi et quand.
SELECT throws_ok(
    $$UPDATE admin.platform_admin
         SET revoked_at = now(),
             revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.v_c')::uuid
       WHERE id = '77777777-7777-4777-8777-777777777777'$$,
    'AD072', NULL,
    'an authority already revoked cannot be revoked again'
);

-- RÉÉCRIRE LE MOTIF EN RÉVOQUANT. Sur l'octroi client, encore vivant : le motif
-- est ce qu'on relira pour comprendre pourquoi l'accès avait été ouvert.
SELECT throws_ok(
    $$UPDATE admin.admin_tenant
         SET revoked_at = now(),
             revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.vt_c')::uuid,
             reason = 'motif reecrit apres coup'
       WHERE id = '66666666-6666-4666-8666-666666666666'$$,
    'AD072', NULL,
    'only the revocation may be written, never the reason it was granted'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  L'AUTORITÉ DU SIGNATAIRE EST RELUE À L'ÉCRITURE
--
--  On retire ici son autorité à A. Ses commandes restent authentiques — elles
--  l'étaient au moment de la touche — mais il ne peut plus s'en servir. C'est
--  la course que seule une relecture À L'USAGE attrape : une vérification faite
--  au moment de signer aurait eu lieu, et aurait dit vrai.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$
DECLARE
    c uuid := current_setting('essai.c')::uuid;
BEGIN
    UPDATE admin.platform_admin
       SET revoked_at = now(), revoked_by = c,
           revoked_command_id = pg_temp.commande(
               c,
               (SELECT id FROM admin.session WHERE user_id = c),
               (SELECT id FROM akeys.key WHERE user_id = c),
               'authority.revoke', '68')
     WHERE user_id = current_setting('essai.a')::uuid;
END $$;

SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, approved_by, command_id, request_id)
      VALUES (current_setting('essai.d')::uuid,
              current_setting('essai.a')::uuid, 'astreinte',
              current_setting('essai.c')::uuid,
              current_setting('essai.g_a')::uuid,
              current_setting('essai.r1')::uuid)$$,
    'AD079', NULL,
    'an admin whose own authority lapsed can no longer grant with it'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  RIEN NE S'EFFACE
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$DELETE FROM admin.platform_admin
       WHERE id = '77777777-7777-4777-8777-777777777777'$$,
    'AD071', NULL,
    'an authority is never deleted, only dated'
);

SELECT is(
    (SELECT count(*)::int FROM admin.platform_admin
      WHERE id = '77777777-7777-4777-8777-777777777777'
        AND revoked_at IS NOT NULL
        AND reason = 'astreinte'),
    1,
    'the revoked grant is still there, with the reason it was granted for'
);

SELECT * FROM finish();
