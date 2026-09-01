-- CE QU'UN ADMINISTRATEUR VOIT, ET SURTOUT CE QU'IL NE VOIT PAS.
--
-- ═══ POURQUOI CE FICHIER EST LE PLUS IMPORTANT DU DOSSIER ═══
--
-- Douze politiques de sécurité de ligne gardent cette base. AVANT CE BANC,
-- AUCUNE N'AVAIT JAMAIS ÉTÉ EXÉCUTÉE — pas une seule fois, ni en test ni
-- ailleurs.
--
-- La raison est structurelle et se lit en une ligne : tous les autres bancs se
-- connectent en SUPERUTILISATEUR, et un superutilisateur contourne le RLS par
-- conception. Le rapport du mutant le disait sans détour — les cinq
-- `tenant_visible` et les sept `own_or_platform` survivaient, campagne après
-- campagne. Un schéma multi-client dont le cloisonnement n'a jamais tourné.
--
-- `doctrine.sql` prouve que chaque vue porte `security_invoker`, donc qu'elle
-- S'EXÉCUTERAIT avec les droits de son appelant. Il ne prouve pas qu'une fois
-- exécutée, `may_read` filtre quoi que ce soit. C'est toute la différence entre
-- « la serrure est posée » et « la serrure ferme ».
--
-- Ce banc est donc le seul du dépôt qui emprunte le CHEMIN RÉEL de
-- l'application : `SET LOCAL ROLE app_admin_plane`, un administrateur lié à la
-- session, et des comptages.
--
-- ═══ LA LECTURE PASSE TROIS PORTES, DANS CET ORDRE ═══
--
--   app_admin()    qui lit ? Lu dans `app.admin`, posé par transaction depuis
--                  le jeton qu'on vient de valider. Absent : `AD100`, et non
--                  une vue élargie.
--   may_reside()   sous quelle JURIDICTION ? Le client vit dans une région ;
--                  l'opérateur doit y être accrédité. Client sans résidence
--                  déclarée : FERMÉ, pas ouvert en attendant.
--   may_operate()  et seulement alors : en a-t-il l'autorité ?
--
-- L'ORDRE EST L'INVARIANT. La résidence passe AVANT l'autorité, donc une
-- autorité de plateforme ne franchit pas une frontière juridique. C'est
-- l'assertion la plus contre-intuitive de ce fichier, et celle qu'un
-- refactoring casserait sans bruit.
--
-- ═══ DEUX FAMILLES DE POLITIQUES, DEUX RÈGLES DIFFÉRENTES ═══
--
--   tenant_visible    5 tables    may_read(tenant_id) — la juridiction mord
--   own_or_platform   7 tables    la sienne, OU tout si l'on est de la
--                                 plateforme — sans passer par la résidence
--
-- L'asymétrie est délibérée : une session ou une clé n'appartient à aucun
-- client, il n'y a donc pas de juridiction à faire respecter. Les deux
-- familles sont éprouvées ici, précisément parce qu'elles ne disent pas la
-- même chose.
--
-- ═══ CE QUE CE BANC TUE, MESURÉ ═══
--
-- Quinze objets, et la famille `politique` passe de 7 tués sur 24 à 20 :
--
--   politique     tenant_visible × 5        les cinq tables à périmètre client
--   politique     own_or_platform × 6       session, clé, défi, paire, identité,
--                                           résidence d'opérateur
--   politique     owner_is_the_vetted_path × 2
--   fonction      admin.may_reside          la porte juridictionnelle
--   déclencheur   identity_bind_once
--
-- QUATRE SURVIVENT, et chacune pour une raison écrite :
--
--   own_or_platform sur `akeys.key`   inatteignable — voir plus bas
--   owner_is_the_vetted_path sur `identity`, `impersonation`, `token_pair`
--                                     aucune fonction SECURITY DEFINER du
--                                     montage ne lit ces trois tables, donc
--                                     rien ne devient aveugle en la retirant
--
-- Le compte de la base entière vit dans `packages/harnais/mutation-sql.mjs`.
--
-- ═══ LE MONTAGE ═══
--
--   C   l'administrateur d'amorçage — monte le décor, ne lit rien
--   P   un second administrateur de PLATEFORME, accrédité en EU_WEST seulement
--   W1  administrateur du client T1 (EU_WEST)
--   W2  administrateur du client T2 (US_EAST)
--   T3  un client SANS résidence déclarée
--
-- Le décor se pose en superutilisateur ; les assertions se jouent sous le rôle
-- applicatif. `SET LOCAL` partout : la transaction que le lanceur annule remet
-- le rôle et la liaison en place quoi qu'il arrive.

SET search_path TO pgtap, public;

SELECT plan(32);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE, EN SUPERUTILISATEUR
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
    p  uuid := gen_random_uuid();
    w1 uuid := gen_random_uuid();
    w2 uuid := gen_random_uuid();
    s1 uuid := gen_random_uuid();
    s2 uuid := gen_random_uuid();
    t1 uuid := gen_random_uuid();
    t2 uuid := gen_random_uuid();
    t3 uuid := gen_random_uuid();
    sc uuid := gen_random_uuid();  sp uuid := gen_random_uuid();
    s_1 uuid := gen_random_uuid(); s_2 uuid := gen_random_uuid();
    kc uuid := gen_random_uuid();  kp uuid := gen_random_uuid();
    k_1 uuid := gen_random_uuid(); k_2 uuid := gen_random_uuid();
BEGIN
    INSERT INTO admin."user" (id) VALUES (p), (w1), (w2), (s1), (s2);
    PERFORM pg_temp.poste(c, sc, kc);

    -- P : second administrateur de plateforme. Il en faut DEUX —
    -- `operator_residency_not_for_oneself` interdit de se déclarer sa propre
    -- juridiction, ce qui est la même règle que « personne ne se donne
    -- l'autorité », appliquée à la géographie.
    INSERT INTO admin.platform_admin
        (user_id, granted_by, reason, break_glass, command_id)
    VALUES (p, c, 'Lecteur de plateforme du banc', true,
            pg_temp.commande(c, sc, kc, 'authority.grant', '60'));

    PERFORM pg_temp.poste(p, sp, kp);
    PERFORM pg_temp.poste(w1, s_1, k_1);
    PERFORM pg_temp.poste(w2, s_2, k_2);

    -- ═══ LES JURIDICTIONS ═══
    INSERT INTO admin.residency_region (code, description, jurisdiction)
    VALUES ('EU_WEST', 'Europe de l ouest', 'RGPD'),
           ('US_EAST', 'Cote est des Etats-Unis', 'CLOUD Act')
    ON CONFLICT (code) DO NOTHING;

    INSERT INTO admin.operator_residency
        (user_id, region_code, reason, granted_by, command_id)
    VALUES (p,  'EU_WEST', 'Astreinte europeenne', c,
            pg_temp.commande(c, sc, kc, 'residency.grant', '61')),
           (w1, 'EU_WEST', 'Exploitation T1', c,
            pg_temp.commande(c, sc, kc, 'residency.grant', '62')),
           (w2, 'US_EAST', 'Exploitation T2', c,
            pg_temp.commande(c, sc, kc, 'residency.grant', '63'));

    -- T1 et T2 sont domiciliés ; T3 ne l'est PAS, et c'est le sujet d'un test.
    INSERT INTO admin.tenant_residency (tenant_id, region_code, declared_by, command_id)
    VALUES (t1, 'EU_WEST', c,
            pg_temp.commande(c, sc, kc, 'residency.declare', '64', 'TENANT', t1)),
           (t2, 'US_EAST', c,
            pg_temp.commande(c, sc, kc, 'residency.declare', '65', 'TENANT', t2));

    -- ═══ LES AUTORITÉS DE CLIENT ═══
    INSERT INTO admin.admin_tenant (user_id, tenant_id, granted_by, reason, command_id)
    VALUES (w1, t1, c, 'Exploitation T1',
            pg_temp.commande(c, sc, kc, 'authority.grant', '66', 'TENANT', t1)),
           (w2, t2, c, 'Exploitation T2',
            pg_temp.commande(c, sc, kc, 'authority.grant', '67', 'TENANT', t2));

    -- ═══ DES LIGNES DE CHAQUE CÔTÉ DE LA FRONTIÈRE ═══
    INSERT INTO admin.authority_request
        (scope, tenant_id, subject_user_id, reason, requested_by, request_command_id)
    VALUES ('TENANT', t1, s1, 'astreinte T1', c,
            pg_temp.commande(c, sc, kc, 'authority.request', '68', 'TENANT', t1)),
           ('TENANT', t2, s2, 'astreinte T2', c,
            pg_temp.commande(c, sc, kc, 'authority.request', '69', 'TENANT', t2)),
           ('TENANT', t3, s1, 'astreinte T3 sans residence', c,
            pg_temp.commande(c, sc, kc, 'authority.request', '6c', 'TENANT', t3));

    INSERT INTO admin.impersonation
        (command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, expires_at)
    VALUES (pg_temp.commande(p, sp, kp, 'tenant.impersonate', '6a', 'TENANT', t1),
            p, t1, gen_random_uuid(), 'INC-T1', 'reproduction',
            now() + interval '10 minutes'),
           (pg_temp.commande(w2, s_2, k_2, 'tenant.impersonate', '6b', 'TENANT', t2),
            w2, t2, gen_random_uuid(), 'INC-T2', 'reproduction',
            now() + interval '10 minutes');

    -- ═══ UN LOT DE COMMANDES DE CHAQUE CÔTÉ ═══
    --
    -- `admin.command_batch` porte `target_tenant_id` et n'avait AUCUNE
    -- politique jusqu'à `a_granted_view_must_open` : l'ouvrir au plan
    -- applicatif sans la poser aurait rendu lisible à tout administrateur
    -- l'empreinte du manifeste, le nombre de gestes et le signataire de
    -- n'importe quel client. Un lot n'est qu'un regroupement de commandes
    -- signées ; il se cache comme elles.
    INSERT INTO webauthn.challenge
        (id, user_id, session_id, challenge, action, expires_at, scope,
         target_tenant_id, consumed_at)
    VALUES ('77777777-7777-4777-8777-777777777771', c, sc, '\x70707070'::bytea,
            'batch.sign', now() + interval '5 minutes', 'TENANT', t1, now()),
           ('77777777-7777-4777-8777-777777777772', c, sc, '\x71717171'::bytea,
            'batch.sign', now() + interval '5 minutes', 'TENANT', t2, now());

    INSERT INTO admin.command_batch
        (user_id, session_id, challenge_id, scope, target_tenant_id,
         manifest_digest, declared_count)
    VALUES (c, sc, '77777777-7777-4777-8777-777777777771', 'TENANT', t1,
            decode(repeat('70', 32), 'hex'), 2),
           (c, sc, '77777777-7777-4777-8777-777777777772', 'TENANT', t2,
            decode(repeat('71', 32), 'hex'), 2);

    -- ═══ DE QUOI ÉPROUVER `own_or_platform` DES DEUX CÔTÉS ═══
    --
    -- Une ligne À SOI et une ligne À L'AUTRE pour chacune des tables
    -- personnelles. Sans la première, retirer la politique donnerait zéro
    -- partout — et l'assertion « je ne vois pas celle du voisin » passerait
    -- encore. C'est exactement ce que le mutant a reproché à la version
    -- précédente de ce fichier.
    INSERT INTO webauthn.authenticator (user_id, credential_id, public_key, sign_count)
    VALUES (w1, '\xc1e1'::bytea, '\x01'::bytea, 1),
           (w2, '\xc2e2'::bytea, '\x02'::bytea, 1);

    -- Un défi pour W1 : les siens n'existent pas encore, il n'a signé aucune
    -- commande. Non consommé, ce qui n'intéresse pas la politique.
    INSERT INTO webauthn.challenge
        (user_id, session_id, challenge, action, expires_at, scope)
    VALUES (w1, s_1, '\xd1d1d1d1'::bytea, 'authority.request',
            now() + interval '5 minutes', 'PLATFORM');

    INSERT INTO admin.token_pair
        (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
    VALUES (s_1, gen_random_uuid(), gen_random_uuid(), now() + interval '10 minutes'),
           (s_2, gen_random_uuid(), gen_random_uuid(), now() + interval '10 minutes');

    INSERT INTO admin.identity (user_id, provider, provider_id)
    VALUES (w1, 'ENTRA', 'w1@banc'), (w2, 'ENTRA', 'w2@banc');

    PERFORM set_config('essai.p',  p::text,  false);
    PERFORM set_config('essai.w1', w1::text, false);
    PERFORM set_config('essai.w2', w2::text, false);
    PERFORM set_config('essai.t1', t1::text, false);
    PERFORM set_config('essai.t2', t2::text, false);
    PERFORM set_config('essai.t3', t3::text, false);
    PERFORM set_config('essai.s_1', s_1::text, false);
    PERFORM set_config('essai.s_2', s_2::text, false);
END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.tenant_residency
      WHERE tenant_id IN (current_setting('essai.t1')::uuid,
                          current_setting('essai.t2')::uuid)),
    2,
    'the fixture stands: two tenants, two jurisdictions'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  ON QUITTE LE SUPERUTILISATEUR
--
--  Tout ce qui suit s'exécute comme l'application. `SET LOCAL` : la transaction
--  que le lanceur annule rend le rôle quoi qu'il arrive.
-- ═══════════════════════════════════════════════════════════════════════════

-- LE RÔLE APPLICATIF N'A RIEN À FAIRE DANS `pgtap`, et c'est très bien ainsi :
-- LE RÔLE APPLICATIF N'A RIEN À FAIRE DANS `pgtap`, et c'est très bien ainsi :
-- l'extension n'existe que pour les bancs. Mais un schéma sur lequel on n'a pas
-- `USAGE` est IGNORÉ EN SILENCE dans le `search_path` — `is()` répondrait « la
-- fonction n'existe pas », ce qui envoie chercher très loin.
--
-- On l'ouvre donc ici, dans la transaction que le lanceur annule. Rien n'en
-- sort, et surtout : la production n'a pas à porter une permission dont seul ce
-- fichier a besoin.
GRANT USAGE ON SCHEMA pgtap TO app_admin_plane;

SET LOCAL ROLE app_admin_plane;

-- ═══════════════════════════════════════════════════════════════════════════
--  UN ADMINISTRATEUR DE CLIENT NE VOIT QUE SON CLIENT
--
--  Cinq tables, et DEUX assertions par table. Le couple est obligatoire, et la
--  première version de ce fichier ne l'avait pas : sous `FORCE ROW LEVEL
--  SECURITY`, retirer une politique ne rend pas la table plus visible, il la
--  rend AVEUGLE. « Je ne vois rien du voisin » reste donc vrai quand la serrure
--  a disparu.
--
--  Le mutant l'a dit sans détour : trois politiques sur cinq survivaient à un
--  banc qui prétendait les éprouver. Il faut affirmer ce qu'on VOIT autant que
--  ce qu'on ne voit pas.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN PERFORM set_config('app.admin', current_setting('essai.w1'), true); END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.authority_request
      WHERE tenant_id = current_setting('essai.t1')::uuid),
    1,
    'the tenant admin sees the request of their own tenant'
);

SELECT is(
    (SELECT count(*)::int FROM admin.authority_request
      WHERE tenant_id = current_setting('essai.t2')::uuid),
    0,
    'and none of the other tenant''s, though the row is right there'
);

SELECT is(
    (SELECT count(*)::int FROM admin.admin_tenant
      WHERE tenant_id = current_setting('essai.t1')::uuid),
    1,
    'they see who administers their own tenant'
);

SELECT is(
    (SELECT count(*)::int FROM admin.admin_tenant
      WHERE tenant_id = current_setting('essai.t2')::uuid),
    0,
    'and not who administers the other'
);

-- LA COMMANDE SIGNÉE PORTE LE GESTE. La voir, c'est savoir ce qui a été fait
-- chez le voisin, et par qui.
SELECT ok(
    (SELECT count(*) FROM admin.signed_command
      WHERE target_tenant_id = current_setting('essai.t1')::uuid) > 0,
    'they see what was signed against their own tenant'
);

SELECT is(
    (SELECT count(*)::int FROM admin.signed_command
      WHERE target_tenant_id = current_setting('essai.t2')::uuid),
    0,
    'and nothing of what was signed against the other'
);

SELECT is(
    (SELECT count(*)::int FROM admin.impersonation
      WHERE target_tenant_id = current_setting('essai.t1')::uuid),
    1,
    'they see that an account of their tenant was opened'
);

SELECT is(
    (SELECT count(*)::int FROM admin.impersonation
      WHERE target_tenant_id = current_setting('essai.t2')::uuid),
    0,
    'and not that somebody opened one of the other tenant''s'
);

-- LE LOT SUIT SES COMMANDES. Le voir, c'est apprendre combien de gestes le
-- voisin a préparés, sous quelle empreinte de manifeste, et par qui.
SELECT is(
    (SELECT count(*)::int FROM admin.command_batch
      WHERE target_tenant_id = current_setting('essai.t1')::uuid),
    1,
    'they see the command batch prepared for their own tenant'
);

SELECT is(
    (SELECT count(*)::int FROM admin.command_batch
      WHERE target_tenant_id = current_setting('essai.t2')::uuid),
    0,
    'and not the one prepared for the other'
);

SELECT is(
    (SELECT count(*)::int FROM admin.tenant_residency
      WHERE tenant_id = current_setting('essai.t1')::uuid),
    1,
    'they see under which jurisdiction their tenant lives'
);

SELECT is(
    (SELECT count(*)::int FROM admin.tenant_residency
      WHERE tenant_id = current_setting('essai.t2')::uuid),
    0,
    'and not under which the other does'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LA JURIDICTION PASSE AVANT L'AUTORITÉ
--
--  P détient la plateforme ENTIÈRE. Il est accrédité en EU_WEST, et pas
--  ailleurs. `may_read` appelle `may_reside` EN PREMIER : son autorité s'arrête
--  donc à la frontière.
--
--  C'est l'assertion la plus contre-intuitive du fichier. Inverser les deux
--  appels dans `may_read` — ce qu'un jour quelqu'un fera « pour lire moins de
--  tables » — ouvrirait US_EAST à toute la plateforme sans rien casser d'autre.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN PERFORM set_config('app.admin', current_setting('essai.p'), true); END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.authority_request
      WHERE tenant_id = current_setting('essai.t1')::uuid),
    1,
    'the platform admin sees the tenant they are accredited for'
);

SELECT is(
    (SELECT count(*)::int FROM admin.authority_request
      WHERE tenant_id = current_setting('essai.t2')::uuid),
    0,
    'platform authority does not cross a jurisdiction it was not granted'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  FERMÉ PAR DÉFAUT
--
--  T3 existe, porte des lignes, et n'a AUCUNE résidence déclarée. Il n'est pas
--  « ouvert en attendant que quelqu'un se prononce » : il est fermé, y compris
--  à la plateforme.
-- ═══════════════════════════════════════════════════════════════════════════

SELECT is(
    (SELECT count(*)::int FROM admin.authority_request
      WHERE tenant_id = current_setting('essai.t3')::uuid),
    0,
    'a tenant with no declared residency is closed, not open by default'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  SANS ADMINISTRATEUR LIÉ, ON NE LIT RIEN
--
--  L'oubli le plus banal du code appelant. Il doit RÉPONDRE, pas élargir.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN PERFORM set_config('app.admin', '', true); END $$;

SELECT throws_ok(
    'SELECT count(*) FROM admin.authority_request',
    'AD100', NULL,
    'a query with no admin bound to the session is refused, not widened'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  CE QUI EST À SOI
--
--  Six tables, une autre règle : la sienne, ou tout si l'on est de la
--  plateforme. Pas de juridiction ici — une session n'appartient à aucun
--  client, il n'y a rien à cloisonner géographiquement.
--
--  Même discipline que plus haut : ce qu'on voit, ET ce qu'on ne voit pas.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN PERFORM set_config('app.admin', current_setting('essai.w1'), true); END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.session
      WHERE id = current_setting('essai.s_1')::uuid),
    1,
    'an admin sees their own session'
);

SELECT is(
    (SELECT count(*)::int FROM admin.session
      WHERE id = current_setting('essai.s_2')::uuid),
    0,
    'and not somebody else''s'
);

SELECT is(
    (SELECT count(*)::int FROM webauthn.authenticator
      WHERE user_id = current_setting('essai.w1')::uuid),
    1,
    'they see the hardware key they registered'
);

SELECT is(
    (SELECT count(*)::int FROM webauthn.authenticator
      WHERE user_id = current_setting('essai.w2')::uuid),
    0,
    'and not the one somebody else registered'
);

-- LE DÉFI SE RATTACHE PAR SA SESSION, et non par un `user_id` posé dessus.
-- Deux façons d'écrire la même politique, dont une seule survit à un défi dont
-- on aurait oublié de remplir le porteur.
SELECT ok(
    (SELECT count(*) FROM webauthn.challenge
      WHERE session_id = current_setting('essai.s_1')::uuid) > 0,
    'they see the presence proofs of their own session'
);

SELECT is(
    (SELECT count(*)::int FROM webauthn.challenge
      WHERE session_id = current_setting('essai.s_2')::uuid),
    0,
    'and none of another session''s'
);

-- LA PAIRE DE JETONS SUIT LE MÊME CHEMIN INDIRECT. Voir celle d'un autre, c'est
-- voir de quoi se faire passer pour lui.
SELECT is(
    (SELECT count(*)::int FROM admin.token_pair
      WHERE session_id = current_setting('essai.s_1')::uuid),
    1,
    'they see the token pair of their own session'
);

SELECT is(
    (SELECT count(*)::int FROM admin.token_pair
      WHERE session_id = current_setting('essai.s_2')::uuid),
    0,
    'and not the one that would let them be somebody else'
);

SELECT is(
    (SELECT count(*)::int FROM admin.identity
      WHERE user_id = current_setting('essai.w1')::uuid),
    1,
    'they see their own federated identity'
);

SELECT is(
    (SELECT count(*)::int FROM admin.identity
      WHERE user_id = current_setting('essai.w2')::uuid),
    0,
    'and not somebody else''s'
);

SELECT is(
    (SELECT count(*)::int FROM admin.operator_residency
      WHERE user_id = current_setting('essai.w1')::uuid),
    1,
    'they see the jurisdiction they are accredited for'
);

SELECT is(
    (SELECT count(*)::int FROM admin.operator_residency
      WHERE user_id = current_setting('essai.w2')::uuid),
    0,
    'and not who else is accredited where'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  ET L'AUTRE MOITIÉ DE LA RÈGLE
--
--  `own_or_platform` dit « la sienne OU tout ». La seconde branche existe pour
--  que la plateforme puisse enquêter — et elle ne passe PAS par la résidence,
--  puisqu'une session n'a pas de client.
-- ═══════════════════════════════════════════════════════════════════════════

DO $$ BEGIN PERFORM set_config('app.admin', current_setting('essai.p'), true); END $$;

SELECT is(
    (SELECT count(*)::int FROM admin.session
      WHERE id = current_setting('essai.s_2')::uuid),
    1,
    'a platform admin sees any session — no jurisdiction gates what has no tenant'
);

SELECT is(
    (SELECT count(*)::int FROM admin.identity
      WHERE user_id = current_setting('essai.w2')::uuid),
    1,
    'and any identity, for the same reason'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  DE RETOUR EN SUPERUTILISATEUR
--
--  La preuve que tout ce qui précède parlait bien de FILTRAGE, et non de lignes
--  qui n'auraient jamais existé.
-- ═══════════════════════════════════════════════════════════════════════════

RESET ROLE;

SELECT is(
    (SELECT count(*)::int FROM admin.authority_request
      WHERE tenant_id = current_setting('essai.t2')::uuid),
    1,
    'the row the tenant admin could not see was there all along'
);

SELECT * FROM finish();
