-- LA COUCHE « QUI VOUS ÊTES » : LE DÉFI, L'IDENTITÉ FÉDÉRÉE, LE COMPTE.
--
-- ═══ TROIS TABLES, UN MÊME MOMENT ═══
--
-- Avant toute autorité, il faut savoir de qui il s'agit. Ces trois tables
-- portent ce moment-là :
--
--   admin."user"        le compte, déclaré par un autre administrateur
--   admin.identity      son rattachement à un fournisseur d'identité
--   webauthn.challenge  la preuve de présence, valable pour UN geste précis
--
-- ═══ LE PÉRIMÈTRE APPARTIENT À L'ACTION, PAS À L'APPELANT ═══
--
-- `admin.command_action.applies_to` dit pour quelle portée chaque verbe existe.
-- `tenant.impersonate` est un geste de CLIENT, `identity.provision` un geste de
-- PLATEFORME. Demander une présence pour le premier en portée plateforme n'est
-- pas une variante : c'est demander autre chose.
--
-- Sans cette garde, un appelant choisirait la portée qui l'arrange, et la
-- concordance vérifiée plus tard entre la commande et son défi porterait sur
-- deux valeurs également fausses.
--
-- ═══ UNE IDENTITÉ EST SOIT LIÉE, SOIT EN ATTENTE ═══
--
--   identity_provider_or_provision   `provider_id` OU `provision_key` — une
--                                    identité sans aucun des deux ne désigne
--                                    personne chez le fournisseur
--   identity_bound_coherent          `provider_id` et `bound_at` vont ensemble :
--                                    on ne peut pas être rattaché sans date, ni
--                                    daté sans rattachement
--
-- La `provision_key` est la clé d'attente : elle nomme quelqu'un AVANT sa
-- première connexion. Le `provider_id`, lui, arrive avec elle.

SET search_path TO pgtap, public;

SELECT plan(20);

-- ─────────────────────────────────────────────────────────────────────────
--  LE MONTAGE
-- ─────────────────────────────────────────────────────────────────────────

DO $$
DECLARE
    c uuid := (SELECT user_id FROM admin.platform_admin WHERE revoked_at IS NULL LIMIT 1);
    u uuid := gen_random_uuid();
    v uuid := gen_random_uuid();
    w uuid := gen_random_uuid();
BEGIN
    -- W sert les cas d'identite : `C` en porte deja une chez ENTRA, posee par
    -- la migration d'amorcage, et `uq_identity_user_provider` parlerait avant la
    -- contrainte visee.
    INSERT INTO admin."user" (id) VALUES (u), (v), (w);

    INSERT INTO admin.session (id, user_id, absolute_expires_at)
    VALUES ('0701aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', u, now() + interval '1 hour'),
           ('0702aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', v, now() + interval '1 hour');

    PERFORM set_config('essai.c', c::text, false);
    PERFORM set_config('essai.u', u::text, false);
    PERFORM set_config('essai.v', v::text, false);
    PERFORM set_config('essai.w', w::text, false);
END $$;

SELECT isnt(
    nullif(current_setting('essai.u', true), ''),
    NULL,
    'the two accounts and their sessions exist'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE DÉFI
-- ═══════════════════════════════════════════════════════════════════════════

SELECT lives_ok(
    $$INSERT INTO webauthn.challenge
        (user_id, session_id, challenge, action, expires_at, scope)
      VALUES (current_setting('essai.u')::uuid,
              '0701aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '\xd001'::bytea, 'authority.request',
              now() + interval '5 minutes', 'PLATFORM')$$,
    'a presence challenge is posted'
);

-- LE VERBE VIENT DU VOCABULAIRE. Un défi pour un geste inventé ne pourrait
-- correspondre à aucune commande, et la concordance vérifiée plus tard
-- porterait sur du vide des deux côtés.
SELECT throws_ok(
    $$INSERT INTO webauthn.challenge
        (user_id, session_id, challenge, action, expires_at, scope)
      VALUES (current_setting('essai.u')::uuid,
              '0701aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '\xd002'::bytea, 'authority.invente',
              now() + interval '5 minutes', 'PLATFORM')$$,
    '23503', NULL,
    'a challenge for a verb outside the vocabulary is refused'
);

-- LE PÉRIMÈTRE APPARTIENT À L'ACTION. `tenant.impersonate` est un geste de
-- client : le demander en portée plateforme n'est pas une variante, c'est
-- demander autre chose.
SELECT throws_ok(
    $$INSERT INTO webauthn.challenge
        (user_id, session_id, challenge, action, expires_at, scope)
      VALUES (current_setting('essai.u')::uuid,
              '0701aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '\xd003'::bytea, 'tenant.impersonate',
              now() + interval '5 minutes', 'PLATFORM')$$,
    'AD061', NULL,
    'and one whose scope is not the scope its action lives in'
);

SELECT throws_ok(
    $$INSERT INTO webauthn.challenge
        (user_id, session_id, challenge, action, expires_at, scope)
      VALUES (current_setting('essai.u')::uuid,
              '0701aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '\xd004'::bytea, 'authority.request',
              now() - interval '1 minute', 'PLATFORM')$$,
    '23514', NULL,
    'a challenge born already expired proves nothing'
);

-- LA SESSION D'UN AUTRE. La clé étrangère est COMPOSITE — (session_id,
-- user_id) — sinon une présence prouvée par l'un compterait pour l'autre.
SELECT throws_ok(
    $$INSERT INTO webauthn.challenge
        (user_id, session_id, challenge, action, expires_at, scope)
      VALUES (current_setting('essai.u')::uuid,
              '0702aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '\xd005'::bytea, 'authority.request',
              now() + interval '5 minutes', 'PLATFORM')$$,
    '23503', NULL,
    'nor may a challenge claim one admin while pointing at another''s session'
);

-- LA VALEUR DU DÉFI EST UNIQUE. Deux défis partageant leur valeur rendraient la
-- réponse du matériel ambiguë.
SELECT throws_ok(
    $$INSERT INTO webauthn.challenge
        (user_id, session_id, challenge, action, expires_at, scope)
      VALUES (current_setting('essai.u')::uuid,
              '0701aaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              '\xd001'::bytea, 'authority.request',
              now() + interval '5 minutes', 'PLATFORM')$$,
    '23505', NULL,
    'and no two challenges carry the same value'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  L'IDENTITÉ FÉDÉRÉE
-- ═══════════════════════════════════════════════════════════════════════════

-- EN ATTENTE : une clé de provisionnement, pas encore de rattachement. C'est
-- l'état d'un compte déclaré dont la personne ne s'est jamais connectée.
SELECT lives_ok(
    $$INSERT INTO admin.identity (user_id, provider, provision_key)
      VALUES (current_setting('essai.u')::uuid, 'ENTRA', 'attente@banc')$$,
    'an identity may exist as a provisioning key, before any first login'
);

SELECT lives_ok(
    $$INSERT INTO admin.identity
        (user_id, provider, provider_id, bound_at)
      VALUES (current_setting('essai.v')::uuid, 'ENTRA', 'v@banc', now())$$,
    'or as a binding, which comes with the date it happened'
);

-- NI L'UN NI L'AUTRE NE DÉSIGNE PERSONNE.
SELECT throws_ok(
    $$INSERT INTO admin.identity (user_id, provider)
      VALUES (current_setting('essai.w')::uuid, 'ENTRA')$$,
    '23514', NULL,
    'an identity with neither names nobody at the provider'
);

-- ═══ LA DATE N'EST PAS DEMANDÉE, ELLE EST POSÉE ═══
--
-- `identity_bind_once` écrit `bound_at` lui-même dès qu'un `provider_id`
-- apparaît. Ce n'est pas une commodité : « depuis quand » est la première
-- question d'une enquête, et une date fournie par l'appelant serait une date
-- qu'il choisit.
--
-- La garde CORRIGE au lieu de refuser — la transformer en `RAISE` casserait
-- tous les appelants, et aucun test de refus ne le verrait.
-- L'ÉCRITURE DANS UN BLOC, PAS DANS LA SOUS-REQUÊTE : Postgres refuse une
-- clause `WITH` modifiante ailleurs qu'au premier niveau. On écrit, puis on
-- relit — ce qui est de toute façon plus fidèle à ce que fait un appelant.
DO $$ BEGIN
  INSERT INTO admin.identity (user_id, provider, provider_id)
  VALUES (current_setting('essai.w')::uuid, 'ENTRA', 'w@banc');
END $$;

SELECT ok(
    (SELECT bound_at IS NOT NULL FROM admin.identity
      WHERE user_id = current_setting('essai.w')::uuid),
    'a binding is dated by the schema, not by whoever writes it'
);

-- ═══ ET UN RATTACHEMENT NE SE REFAIT PAS ═══
--
-- Rebrancher le compte fédéré d'un administrateur sur un autre, c'est lui
-- substituer quelqu'un sans rien changer d'autre. Le message du schéma est
-- sans détour : « a bug or an attack ».
SELECT throws_ok(
    $$UPDATE admin.identity SET provider_id = 'quelqu-un-d-autre@banc'
       WHERE user_id = current_setting('essai.w')::uuid$$,
    'AD050', NULL,
    'and never rebound onto another account at the provider'
);

-- EN REVANCHE, LIER UNE IDENTITÉ EN ATTENTE EST LE CHEMIN NORMAL : c'est la
-- première connexion. La date se pose alors toute seule, comme à l'insertion.
DO $$ BEGIN
  UPDATE admin.identity SET provider_id = 'u-arrive@banc'
   WHERE user_id = current_setting('essai.u')::uuid;
END $$;

SELECT ok(
    (SELECT bound_at IS NOT NULL FROM admin.identity
      WHERE user_id = current_setting('essai.u')::uuid),
    'while binding a pending identity is the ordinary first login'
);

-- ET DATÉ SANS RATTACHEMENT : l'autre moitié de la même cohérence.
SELECT throws_ok(
    $$INSERT INTO admin.identity
        (user_id, provider, provision_key, bound_at)
      VALUES (current_setting('essai.w')::uuid, 'ENTRA', 'w-attente@banc', now())$$,
    '23514', NULL,
    'and a date without a binding, which would date nothing'
);

-- UN FOURNISSEUR QUI N'EXISTE PAS. Le vocabulaire des fournisseurs est une
-- table : « ENTRA » et « Entra » ne doivent pas coexister.
SELECT throws_ok(
    $$INSERT INTO admin.identity (user_id, provider, provision_key)
      VALUES (current_setting('essai.w')::uuid, 'GOOGLE', 'w@banc')$$,
    '23503', NULL,
    'a provider outside the vocabulary is refused'
);

-- UN COMPTE, UNE IDENTITÉ PAR FOURNISSEUR. Deux rattachements chez le même
-- fournisseur laisseraient deux chemins de connexion pour un seul compte.
SELECT throws_ok(
    $$INSERT INTO admin.identity (user_id, provider, provision_key)
      VALUES (current_setting('essai.u')::uuid, 'ENTRA', 'doublon@banc')$$,
    '23505', NULL,
    'one account holds one identity per provider, never two'
);

SELECT throws_ok(
    $$DELETE FROM admin.identity
       WHERE user_id = current_setting('essai.u')::uuid$$,
    'AD040', NULL,
    'and an identity is never deleted'
);

-- ═══════════════════════════════════════════════════════════════════════════
--  LE COMPTE
--
--  `user_is_signed` laisse passer la GENÈSE — un compte sans parrain — et rien
--  d'autre. C'est ce qui permet d'amorcer, et ce qui interdit de se déclarer
--  soi-même une fois la base peuplée.
-- ═══════════════════════════════════════════════════════════════════════════

-- UN PARRAIN SANS SA COMMANDE répond `AD051` : `user_is_signed` cherche la
-- commande de provisionnement et n'en trouve pas. Le déclencheur parle avant la
-- contrainte, comme partout ailleurs.
SELECT throws_ok(
    $$INSERT INTO admin."user" (id, provisioned_by)
      VALUES (gen_random_uuid(), current_setting('essai.c')::uuid)$$,
    'AD051', NULL,
    'a sponsor without the command that proves them is refused'
);

-- L'AUTRE MOITIÉ, et c'est la seule façon d'atteindre la contrainte : une
-- commande SANS parrain. Le déclencheur rend la main aussitôt — il ne se
-- prononce que si un auteur est posé — et `user_provisioning_complete` dit
-- alors que les deux vont ensemble.
SELECT throws_ok(
    $$INSERT INTO admin."user" (id, provision_command_id)
      VALUES (gen_random_uuid(), gen_random_uuid())$$,
    '23514', NULL,
    'and a provisioning command with no sponsor names nobody as author'
);

SELECT throws_ok(
    $$DELETE FROM admin."user" WHERE id = current_setting('essai.v')::uuid$$,
    'AD040', NULL,
    'and an account is never deleted, only deactivated'
);

SELECT * FROM finish();
