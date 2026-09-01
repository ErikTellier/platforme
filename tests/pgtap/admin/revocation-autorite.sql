-- COUPER UN ACCÈS, ET CE QUE ÇA EXIGE.
--
-- ═══ POURQUOI CE GESTE COMPTE AUTANT QUE L'OCTROI ═══
--
-- `octroi-autorite.sql` prouve qu'on n'obtient pas l'autorité sans cérémonie.
-- Ce fichier prouve l'autre moitié : qu'on la PERD vraiment quand quelqu'un le
-- décide. Une révocation qui ne mord pas est pire qu'aucune révocation — on
-- croit avoir coupé.
--
-- Et c'est le geste qu'on fait dans l'urgence, souvent de nuit, souvent par
-- quelqu'un qui n'a pas écrit le schéma. Il doit donc refuser tout ce qui n'est
-- pas une révocation en règle, et le dire clairement.
--
-- ═══ UNE RÉVOCATION EST SIGNÉE, COMME UN OCTROI ═══
--
-- `authority_is_signed('…','REVOKE')` exige les quatre mêmes égalités que du
-- côté de l'octroi : la commande dépensée est une `authority.revoke`, sur le
-- bon périmètre, pour le bon client, ET SIGNÉE PAR CELUI QUI RÉVOQUE. Sans la
-- dernière, un administrateur signe et un autre s'en sert.
--
-- ═══ L'ORDRE DES DÉCLENCHEURS, TOUJOURS ALPHABÉTIQUE ═══
--
--   <table>_revocation_is_signed      AD084 AD085   la signature
--   <table>_revocation_only           AD072 AD077   ce qui bouge
--   <table>_revoker_has_authority     AD079         le signataire
--
-- Conséquence mesurée : un auteur SANS AUTORITÉ répond `AD085`, et non `AD079`
-- — parce que la commande qu'il dépense n'est pas signée de sa main. Pour
-- atteindre `AD079`, il faut quelqu'un qui a SIGNÉ pendant qu'il avait
-- l'autorité et l'a perdue depuis. C'est le seul chemin, et c'est aussi le seul
-- cas qui compte vraiment : couper l'accès d'un opérateur doit mordre sur ce
-- qu'il n'a pas encore fait.
--
-- ═══ LES DEUX PORTÉES, PARCE QUE CE SONT DEUX JEUX D'OBJETS ═══
--
-- `platform_admin` et `admin_tenant` partagent leurs fonctions mais ont chacun
-- leurs déclencheurs et leurs contraintes. Les éprouver toutes deux n'est pas
-- une répétition : c'est deux fois plus d'objets, et une politique lue
-- différemment.
--
-- ═══ LE MONTAGE ═══
--
--   C   l'administrateur d'amorçage, qui révoque en règle
--   A   un second administrateur, qui SIGNE puis perd son autorité
--   B   le porteur d'une autorité de plateforme, à révoquer
--   W   le porteur d'une autorité sur le client T, à révoquer

SET search_path TO pgtap, public;

SELECT plan(27);

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
    w  uuid := gen_random_uuid();
    t  uuid := gen_random_uuid();
    sc uuid := gen_random_uuid(); sa uuid := gen_random_uuid();
    kc uuid := gen_random_uuid(); ka uuid := gen_random_uuid();
BEGIN
    PERFORM set_config('app.caller', 'banc-de-revocation', false);
    INSERT INTO admin."user" (id) VALUES (a), (b), (w);
    PERFORM pg_temp.poste(c, sc, kc);

    -- A : second administrateur, par bris de glace comme partout ailleurs.
    INSERT INTO admin.platform_admin (user_id, granted_by, reason, break_glass, command_id)
    VALUES (a, c, 'Second administrateur du banc', true,
            pg_temp.commande(c, sc, kc, 'authority.grant', '60'));

    PERFORM pg_temp.poste(a, sa, ka);

    -- B reçoit une autorité de plateforme, par bris de glace : ce banc éprouve
    -- la RÉVOCATION, et refaire la cérémonie complète d'octroi ne mettrait rien
    -- de plus à l'épreuve — `octroi-autorite.sql` s'en charge.
    INSERT INTO admin.platform_admin
        (id, user_id, granted_by, reason, break_glass, command_id)
    VALUES ('cafe1111-1111-4111-8111-111111111111', b, c,
            'Astreinte de nuit', true,
            pg_temp.commande(c, sc, kc, 'authority.grant', '61'));

    -- W reçoit une autorité sur T. La portée client n'exige ni demande ni
    -- second approbateur.
    INSERT INTO admin.admin_tenant
        (id, user_id, tenant_id, granted_by, reason, command_id)
    VALUES ('cafe2222-2222-4222-8222-222222222222', w, t, c, 'Exploitation T',
            pg_temp.commande(c, sc, kc, 'authority.grant', '62', 'TENANT', t));

    PERFORM set_config('essai.c', c::text, false);
    PERFORM set_config('essai.a', a::text, false);
    PERFORM set_config('essai.b', b::text, false);
    PERFORM set_config('essai.w', w::text, false);
    PERFORM set_config('essai.t', t::text, false);

    -- Les commandes de révocation. Celles de A sont signées MAINTENANT, pendant
    -- qu'il détient encore l'autorité : c'est ce qui rend le dernier cas
    -- possible.
    PERFORM set_config('essai.v_c',
        pg_temp.commande(c, sc, kc, 'authority.revoke', '63')::text, false);
    PERFORM set_config('essai.v_a',
        pg_temp.commande(a, sa, ka, 'authority.revoke', '64')::text, false);
    PERFORM set_config('essai.vt_c',
        pg_temp.commande(c, sc, kc, 'authority.revoke', '65', 'TENANT', t)::text, false);
    PERFORM set_config('essai.vt_a',
        pg_temp.commande(a, sa, ka, 'authority.revoke', '66', 'TENANT', t)::text, false);
    -- Une révocation de plateforme, là où il faudrait celle d'un client.
    PERFORM set_config('essai.v_c2',
        pg_temp.commande(c, sc, kc, 'authority.revoke', '67')::text, false);
    -- Et un octroi de client signé par A, pour la garde du signataire.
    PERFORM set_config('essai.gt_a',
        pg_temp.commande(a, sa, ka, 'authority.grant', '68', 'TENANT', t)::text, false);

    -- Six octrois signés par C, pour les clés étrangères que rien n'ombrage.
    PERFORM set_config('essai.g1',
        pg_temp.commande(c, sc, kc, 'authority.grant', '69')::text, false);
    PERFORM set_config('essai.g2',
        pg_temp.commande(c, sc, kc, 'authority.grant', '6a')::text, false);
    PERFORM set_config('essai.g3',
        pg_temp.commande(c, sc, kc, 'authority.grant', '6b')::text, false);
    PERFORM set_config('essai.gt1',
        pg_temp.commande(c, sc, kc, 'authority.grant', '6c', 'TENANT', t)::text, false);
    PERFORM set_config('essai.gt2',
        pg_temp.commande(c, sc, kc, 'authority.grant', '6d', 'TENANT', t)::text, false);
    PERFORM set_config('essai.gt3',
        pg_temp.commande(c, sc, kc, 'authority.grant', '6e', 'TENANT', t)::text, false);
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.platform_admin
      WHERE id = 'cafe1111-1111-4111-8111-111111111111' AND revoked_at IS NULL),
    1,
    'the authority to be cut is live before we start'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CE QU'UNE RÉVOCATION EXIGE
--
--  Tous ces refus portent sur la MÊME ligne vivante, et aucun ne la modifie.
--  Le cas qui passe vient donc en dernier, pour que chaque refus soit joué
--  contre une autorité réellement en vigueur.
-- ═══════════════════════════════════════════════════════════════════════════

-- UNE DATE SANS AUTEUR. « Révoquée » sans dire par qui laisse la question la
-- plus importante d'un incident sans réponse.
SELECT throws_ok(
    $$UPDATE admin.platform_admin SET revoked_at = now()
       WHERE id = 'cafe1111-1111-4111-8111-111111111111'$$,
    '23514', NULL,
    'a revocation without an author is refused'
);

-- ET UN AUTEUR SANS DATE. L'autre moitié : la ligne se dirait révoquée par
-- quelqu'un sans jamais l'être.
SELECT throws_ok(
    $$UPDATE admin.platform_admin
         SET revoked_by = current_setting('essai.c')::uuid
       WHERE id = 'cafe1111-1111-4111-8111-111111111111'$$,
    '23514', NULL,
    'and an author without a date, which would revoke nothing at all'
);

-- SANS COMMANDE SIGNÉE. Une révocation est un geste de plateforme comme un
-- autre : elle se prouve par une touche matérielle.
SELECT throws_ok(
    $$UPDATE admin.platform_admin
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid
       WHERE id = 'cafe1111-1111-4111-8111-111111111111'$$,
    'AD084', NULL,
    'a revocation without a signed command is refused'
);

-- LA COMMANDE D'UN AUTRE. C'est le cas qui compte : un administrateur signe, un
-- autre s'en sert, et la trace désigne le mauvais.
SELECT throws_ok(
    $$UPDATE admin.platform_admin
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.v_a')::uuid
       WHERE id = 'cafe1111-1111-4111-8111-111111111111'$$,
    'AD085', NULL,
    'nor one leaning on a command somebody else signed'
);

-- RÉVOQUER AVANT D'AVOIR ACCORDÉ. Une trace qui se lit à l'envers ne se lit
-- pas.
SELECT throws_ok(
    $$UPDATE admin.platform_admin
         SET revoked_at = granted_at - interval '1 hour',
             revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.v_c')::uuid
       WHERE id = 'cafe1111-1111-4111-8111-111111111111'$$,
    '23514', NULL,
    'nor a revocation dated before the grant it ends'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  L'AUTORITÉ DU RÉVOCATEUR EST RELUE À L'ÉCRITURE
--
--  A a signé sa commande de révocation pendant qu'il détenait l'autorité. On
--  la lui retire, puis il essaie de s'en servir.
--
--  C'EST LE SEUL CHEMIN VERS `AD079`. Un auteur qui n'a jamais eu l'autorité
--  n'a pas pu signer, et sa tentative répond `AD085` — la commande n'est pas de
--  lui. Mesuré, pas supposé.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN
  UPDATE admin.platform_admin
     SET revoked_at = now(),
         revoked_by = current_setting('essai.c')::uuid,
         revoked_command_id = current_setting('essai.v_c')::uuid
   WHERE user_id = current_setting('essai.a')::uuid;
END $$;

SELECT throws_ok(
    $$UPDATE admin.platform_admin
         SET revoked_at = now(), revoked_by = current_setting('essai.a')::uuid,
             revoked_command_id = current_setting('essai.v_a')::uuid
       WHERE id = 'cafe1111-1111-4111-8111-111111111111'$$,
    'AD079', NULL,
    'an admin who lost their own authority can no longer cut somebody else''s'
);

-- ET DU CÔTÉ DE L'OCTROI, la même règle : A ne peut plus accorder non plus.
SELECT throws_ok(
    $$INSERT INTO admin.admin_tenant
        (user_id, tenant_id, granted_by, reason, command_id)
      VALUES (current_setting('essai.b')::uuid,
              current_setting('essai.t')::uuid,
              current_setting('essai.a')::uuid, 'Exploitation',
              current_setting('essai.gt_a')::uuid)$$,
    'AD079', NULL,
    'nor grant a tenant authority with the one they no longer hold'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA RÉVOCATION EN RÈGLE
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$UPDATE admin.platform_admin
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.v_c')::uuid
       WHERE id = 'cafe1111-1111-4111-8111-111111111111'$$,
    'a platform authority is cut by a signed command, from someone who holds it'
);

-- ET L'ACCÈS TOMBE VRAIMENT. Sans cette assertion, tout ce qui précède
-- décrirait une colonne qu'on remplit, pas un droit qu'on retire.
SELECT ok(
    NOT admin.may_operate(current_setting('essai.b')::uuid, NULL),
    'and the person may no longer operate — the column is not the point, this is'
);

-- LE MOTIF DE L'OCTROI SURVIT À SA RÉVOCATION. C'est ce qu'on relira pour
-- comprendre pourquoi l'accès avait été ouvert.
SELECT is(
    (SELECT reason FROM admin.platform_admin
      WHERE id = 'cafe1111-1111-4111-8111-111111111111'),
    'Astreinte de nuit',
    'while the reason it was ever granted stays readable'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA PORTÉE CLIENT : LES MÊMES FONCTIONS, D'AUTRES OBJETS
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$UPDATE admin.admin_tenant SET revoked_at = now()
       WHERE id = 'cafe2222-2222-4222-8222-222222222222'$$,
    '23514', NULL,
    'a tenant revocation without an author is refused too'
);

SELECT throws_ok(
    $$UPDATE admin.admin_tenant
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid
       WHERE id = 'cafe2222-2222-4222-8222-222222222222'$$,
    'AD084', NULL,
    'and so is one without a signed command'
);

-- LA COMMANDE DOIT NOMMER LE BON CLIENT. Une révocation de plateforme ne coupe
-- pas un accès de client : ce serait couper autre chose que ce qu'on a signé.
SELECT throws_ok(
    $$UPDATE admin.admin_tenant
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.v_c2')::uuid
       WHERE id = 'cafe2222-2222-4222-8222-222222222222'$$,
    'AD085', NULL,
    'a platform-scoped command does not cut a tenant-scoped authority'
);

SELECT throws_ok(
    $$UPDATE admin.admin_tenant
         SET revoked_at = granted_at - interval '1 hour',
             revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.vt_c')::uuid
       WHERE id = 'cafe2222-2222-4222-8222-222222222222'$$,
    '23514', NULL,
    'nor is a tenant revocation dated before its grant'
);

SELECT throws_ok(
    $$UPDATE admin.admin_tenant
         SET revoked_at = now(), revoked_by = current_setting('essai.a')::uuid,
             revoked_command_id = current_setting('essai.vt_a')::uuid
       WHERE id = 'cafe2222-2222-4222-8222-222222222222'$$,
    'AD079', NULL,
    'and the revoker must still hold authority over that very tenant'
);

SELECT lives_ok(
    $$UPDATE admin.admin_tenant
         SET revoked_at = now(), revoked_by = current_setting('essai.c')::uuid,
             revoked_command_id = current_setting('essai.vt_c')::uuid
       WHERE id = 'cafe2222-2222-4222-8222-222222222222'$$,
    'a tenant authority is cut the same way'
);

SELECT ok(
    NOT admin.may_operate(current_setting('essai.w')::uuid,
                          current_setting('essai.t')::uuid),
    'and that operator loses the tenant they were cut from'
);

SELECT throws_ok(
    $$DELETE FROM admin.admin_tenant
       WHERE id = 'cafe2222-2222-4222-8222-222222222222'$$,
    'AD071', NULL,
    'a cut authority is never deleted — it is the trace of what was open'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CE QUE LES CLÉS ÉTRANGÈRES ATTRAPENT ENCORE
--
--  BEAUCOUP DE CELLES DE CES DEUX TABLES SONT OMBRAGÉES : un déclencheur répond
--  `AD085` avant qu'elles n'aient la parole. Six ne le sont pas, et il a fallu
--  les SONDER une par une pour le savoir — le raisonnement s'était trompé cinq
--  fois de suite. Celles-ci parlent, donc elles s'éprouvent.
--
--  Toutes signées par C, qui détient encore son autorité : sans quoi `AD079`
--  mordrait d'abord et n'affirmerait pas ce qu'on croit.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, break_glass, command_id)
      VALUES (gen_random_uuid(), current_setting('essai.c')::uuid,
              'porteur inconnu', true, current_setting('essai.g1')::uuid)$$,
    '23503', NULL,
    'an authority cannot be granted to somebody who does not exist'
);

SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, break_glass, command_id, approved_by)
      VALUES (current_setting('essai.w')::uuid, current_setting('essai.c')::uuid,
              'approbateur inconnu', true, current_setting('essai.g2')::uuid,
              gen_random_uuid())$$,
    '23503', NULL,
    'nor approved by somebody who does not'
);

-- LA DEMANDE CITÉE DOIT EXISTER. En bris de glace, `grant_follows_a_request`
-- rend la main avant d'avoir rien compare — c'est la clé étrangère qui reste
-- seule à garder la porte.
SELECT throws_ok(
    $$INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, break_glass, command_id, request_id)
      VALUES (current_setting('essai.w')::uuid, current_setting('essai.c')::uuid,
              'demande inventee', true, current_setting('essai.g3')::uuid,
              gen_random_uuid())$$,
    '23503', NULL,
    'nor lean on a request that was never opened'
);

SELECT throws_ok(
    $$INSERT INTO admin.admin_tenant
        (user_id, tenant_id, granted_by, reason, command_id)
      VALUES (gen_random_uuid(), current_setting('essai.t')::uuid,
              current_setting('essai.c')::uuid, 'porteur inconnu',
              current_setting('essai.gt1')::uuid)$$,
    '23503', NULL,
    'the tenant scope refuses an unknown holder just the same'
);

SELECT throws_ok(
    $$INSERT INTO admin.admin_tenant
        (user_id, tenant_id, granted_by, reason, command_id, approved_by)
      VALUES (current_setting('essai.b')::uuid, current_setting('essai.t')::uuid,
              current_setting('essai.c')::uuid, 'approbateur inconnu',
              current_setting('essai.gt2')::uuid, gen_random_uuid())$$,
    '23503', NULL,
    'and an unknown approver'
);

-- UN TERME ANTÉRIEUR À L'OCTROI. La portée client n'exige pas de demande
-- approuvée, donc rien ne mord avant la contrainte — c'est le seul endroit du
-- schéma où celle-ci peut parler.
SELECT throws_ok(
    $$INSERT INTO admin.admin_tenant
        (user_id, tenant_id, granted_by, reason, command_id, expires_at)
      VALUES (current_setting('essai.b')::uuid, current_setting('essai.t')::uuid,
              current_setting('essai.c')::uuid, 'terme a l envers',
              current_setting('essai.gt3')::uuid, now() - interval '1 hour')$$,
    '23514', NULL,
    'an authority may not expire before it was granted'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CE QUE LE JOURNAL EN GARDE
--
--  Une révocation qui ne laisserait pas de trace serait indistinguable d'un
--  accès qui n'a jamais existé.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT is(
    (SELECT changed -> 'revoked_by' ->> 'after' FROM audit.event
      WHERE table_name = 'platform_admin' AND op = 'UPDATE'
        AND row_key ->> 'id' = 'cafe1111-1111-4111-8111-111111111111'),
    current_setting('essai.c'),
    'the journal records who cut the access'
);

-- LE DOCUMENT ENTIER, et non « avant vaut nul » : un champ absent se compare a
-- NULL tout aussi bien, et l'assertion serait vraie sans rien affirmer. Le
-- meme piege que dans `journal.sql`, ou il avait deja fallu le corriger.
SELECT is(
    (SELECT changed -> 'revoked_by' FROM audit.event
      WHERE table_name = 'admin_tenant' AND op = 'UPDATE'
        AND row_key ->> 'id' = 'cafe2222-2222-4222-8222-222222222222'),
    jsonb_build_object('before', NULL, 'after', current_setting('essai.c')),
    'and that nobody had cut it before this very act'
);

SELECT * FROM finish();
