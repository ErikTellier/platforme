-- Up Migration

-- UNE CLÉ, UN USAGE.
--
-- Une session d'administration produit désormais deux sortes de signatures, et
-- elles ne s'adressent pas au même vérificateur :
--
--   COMMAND  la commande signée qu'un service SOUVERAIN vérifie de son côté,
--            contre le JWKS publié. C'est l'usage historique de `akeys`, celui
--            qui fonde la non-répudiation : `kid` → `user_id` → identité.
--
--   SESSION  le bearer et le refresh, que le plan d'administration vérifie POUR
--            LUI-MÊME. Le vérificateur est la base, consultée à chaque requête
--            par `validate_bearer`.
--
-- Signer les deux avec la même clé aurait tenu, à condition de ne jamais
-- relâcher la distinction des audiences — pendant des années, sur tous les
-- chemins. Et ça diluait ce qui fait la valeur de la signature de commande :
-- une clé exercée en permanence par le service, à chaque connexion et à chaque
-- rotation, sans qu'aucun administrateur ait rien fait, cesse de distinguer
-- « l'administrateur a agi » de « le service a émis un cookie ».
--
-- Deux clés, deux durées de vie identiques, deux révocations simultanées : la
-- séparation ne coûte rien puisqu'elles naissent et meurent avec la session.
--
--
-- ═══ POURQUOI UN TYPE ÉNUMÉRÉ, ALORS QUE LES VOCABULAIRES SONT DES TABLES ═══
--
-- `reason_codes_as_data` a sorti les vocabulaires du système de types, et
-- s'arrête exactement là où il faut : « akeys.key_state stays an enum:
-- PENDING/ACTIVE is a state machine, not vocabulary ».
--
-- L'usage d'une clé n'est pas davantage un vocabulaire. C'est une liste
-- d'autorisation fermée, du même genre que `identity_provider` : « adding a
-- provider to the privileged plane is a conscious MIGRATION, never a string
-- someone types ». Un troisième usage changerait ce que signifie une signature
-- dans ce plan — ça se décide, ça ne se saisit pas.
--
--
-- ═══ LE DÉFAUT EST POSÉ PUIS RETIRÉ ═══
--
-- `DEFAULT 'COMMAND'` le temps de la reprise, pour que les clés existantes
-- gardent le sens qu'elles avaient. Puis il disparaît : avec un défaut,
-- l'appelant qui oublie la colonne frappe une clé de commande en croyant
-- frapper une clé de session, et rien ne le lui dit. Sans défaut, il ne peut
-- pas oublier.
--
--
-- ═══ CE QUE LE JWKS CESSE DE PUBLIER ═══
--
-- `verifiable_key` ne rend plus que les clés de COMMANDE. La clé de session
-- n'est vérifiée que par le plan lui-même, qui lit son `public_jwk` en base :
-- la publier n'aiderait personne et exposerait du matériel dont aucun service
-- souverain n'a l'usage. Un JWKS doit contenir ce qu'il faut vérifier, pas tout
-- ce qui existe.
--
--
-- ═══ LES VUES `api` SONT REPRISES UNE À UNE ═══
--
-- Elles ont été écrites en `SELECT *`, ce qui fige la liste des colonnes à la
-- création : ajouter une colonne à la table ne les traverse pas. Sans ces
-- remplacements, l'application ne verrait jamais `purpose` et ne pourrait pas
-- choisir sa clé.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     (aucun — la seconde clé vivante d'un même usage est refusée par
--      uq_key_one_active_per_purpose, donc par un 23505 standard)
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE TYPE akeys.key_purpose AS ENUM ('COMMAND', 'SESSION');

COMMENT ON TYPE akeys.key_purpose IS
  'Ce qu''une clé a le droit de signer. COMMAND : les commandes vérifiées par les services souverains, contre le JWKS. SESSION : le bearer et le refresh, vérifiés par le plan lui-même. Une clé ne fait jamais les deux.';

ALTER TABLE akeys.key
  ADD COLUMN purpose akeys.key_purpose NOT NULL DEFAULT 'COMMAND';
ALTER TABLE akeys.key
  ALTER COLUMN purpose DROP DEFAULT;

COMMENT ON COLUMN akeys.key.purpose IS
  'Sans défaut, délibérément : frapper une clé sans dire ce qu''elle signe doit être impossible, pas silencieusement interprété.';

-- L'invariant se déplace, il ne disparaît pas : au plus une clé vivante par
-- administrateur ET PAR USAGE. Sans ce déplacement, la seconde clé d'une même
-- session serait refusée par l'ancien index.
DROP INDEX akeys.uq_key_one_active_per_admin;

CREATE UNIQUE INDEX uq_key_one_active_per_purpose
  ON akeys.key (user_id, purpose)
  WHERE state = 'ACTIVE' AND private_destroyed_at IS NULL;

COMMENT ON INDEX akeys.uq_key_one_active_per_purpose IS
  'Au plus une clé vivante par administrateur et par usage, garantie par le moteur. Deux connexions concurrentes ne peuvent pas laisser deux clés de commande derrière elles.';

-- ---------------------------------------------------------------------
-- Les vues portent l'usage : sans lui, l'appelant ne peut pas choisir.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW akeys.signing_key AS
  SELECT k.id, k.kid, k.user_id, k.session_id, k.state, k.public_jwk,
         k.created_at, k.activated_at, k.signs_until, k.published_until,
         k.purpose
    FROM akeys.key AS k
    INNER JOIN admin.session AS s ON k.session_id = s.id
   WHERE k.state = 'ACTIVE'
     AND k.private_destroyed_at IS NULL
     AND now() < k.signs_until
     AND s.ended_at IS NULL;

CREATE OR REPLACE VIEW akeys.signing_material AS
  SELECT id, kid, user_id, kms_ref, signs_until, purpose
  FROM akeys.key
  WHERE state = 'ACTIVE'
    AND private_destroyed_at IS NULL
    AND now() < signs_until;

CREATE OR REPLACE VIEW akeys.destroyable_key AS
  SELECT id, kid, user_id, kms_ref, signs_until, purpose
  FROM akeys.key
  WHERE private_destroyed_at IS NULL
    AND now() >= signs_until;

-- Le JWKS ne publie que ce qu'un service souverain doit vérifier.
CREATE OR REPLACE VIEW akeys.verifiable_key AS
  SELECT id, kid, user_id, public_jwk, signs_until, published_until, purpose
  FROM akeys.key
  WHERE state = 'ACTIVE'
    AND now() < published_until
    AND purpose = 'COMMAND';

COMMENT ON VIEW akeys.verifiable_key IS
  'Les clés qu''un service peut vérifier en ce moment, grâce de dix minutes comprise. Matériel public uniquement, et COMMANDE uniquement : la clé de session ne concerne que le plan, qui lit la sienne en base. user_id y figure parce que la vérification doit résoudre kid → administrateur pour l''attribution, ce qui rend cette vue interne — destinée aux services souverains, jamais accrochée à une URL publique, sous peine de publier la liste des administrateurs.';

-- ---------------------------------------------------------------------
-- Le contrat applicatif. Ces vues ont été écrites en SELECT *, qui fige.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW api.key AS
  SELECT id, kid, user_id, session_id, state, public_jwk, kms_ref, created_at,
         activated_at, signs_until, published_until, private_destroyed_at,
         purpose
    FROM akeys.key;

CREATE OR REPLACE VIEW api.signing_key AS
  SELECT id, kid, user_id, session_id, state, public_jwk, created_at, activated_at,
         signs_until, published_until, purpose
    FROM akeys.signing_key;
CREATE OR REPLACE VIEW api.signing_material AS
  SELECT id, kid, user_id, kms_ref, signs_until, purpose
    FROM akeys.signing_material;
CREATE OR REPLACE VIEW api.destroyable_key AS
  SELECT id, kid, user_id, kms_ref, signs_until, purpose
    FROM akeys.destroyable_key;
CREATE OR REPLACE VIEW api.verifiable_key AS
  SELECT id, kid, user_id, public_jwk, signs_until, published_until, purpose
    FROM akeys.verifiable_key;

GRANT SELECT (purpose), INSERT (purpose) ON api.key TO app_admin_plane;

RESET ROLE;

-- Down Migration

--
-- ⚠ L'annulation n'est possible que si AUCUN administrateur ne détient deux
-- clés vivantes : l'ancien index n'en admet qu'une par administrateur, tous
-- usages confondus, et sa recréation échoue en 23505 sinon. Retirer d'abord les
-- clés de session — en posant leur `private_destroyed_at`, puisque `akeys.key`
-- est en append-only. Ce n'est pas un défaut de cette migration : c'est
-- l'invariant qu'elle a desserré, qui se resserre.

SET ROLE admin_owner;

-- CREATE OR REPLACE ne sait qu'AJOUTER des colonnes : rétrécir une vue exige de
-- la détruire, donc de reposer ses droits colonne par colonne.
DROP VIEW api.key;

CREATE VIEW api.key AS
  SELECT id, kid, user_id, session_id, state, public_jwk, kms_ref, created_at,
         activated_at, signs_until, published_until, private_destroyed_at
    FROM akeys.key;

GRANT SELECT (id, kid, user_id, session_id, state, public_jwk, created_at,
              activated_at, signs_until, published_until, private_destroyed_at)
  ON api.key TO app_admin_plane;
GRANT INSERT (kid, user_id, session_id, state, activated_at, public_jwk,
              kms_ref, signs_until, published_until)
  ON api.key TO app_admin_plane;
GRANT UPDATE (state, activated_at, private_destroyed_at)
  ON api.key TO app_admin_plane;

DROP VIEW api.verifiable_key;
DROP VIEW api.destroyable_key;
DROP VIEW api.signing_material;
DROP VIEW api.signing_key;

DROP VIEW akeys.verifiable_key;
DROP VIEW akeys.destroyable_key;
DROP VIEW akeys.signing_material;
DROP VIEW akeys.signing_key;

CREATE VIEW akeys.signing_key AS
  SELECT k.id, k.kid, k.user_id, k.session_id, k.state, k.public_jwk,
         k.created_at, k.activated_at, k.signs_until, k.published_until
    FROM akeys.key AS k
    INNER JOIN admin.session AS s ON k.session_id = s.id
   WHERE k.state = 'ACTIVE'
     AND k.private_destroyed_at IS NULL
     AND now() < k.signs_until
     AND s.ended_at IS NULL;

CREATE VIEW akeys.signing_material AS
  SELECT id, kid, user_id, kms_ref, signs_until
  FROM akeys.key
  WHERE state = 'ACTIVE'
    AND private_destroyed_at IS NULL
    AND now() < signs_until;

CREATE VIEW akeys.destroyable_key AS
  SELECT id, kid, user_id, kms_ref, signs_until
  FROM akeys.key
  WHERE private_destroyed_at IS NULL
    AND now() >= signs_until;

CREATE VIEW akeys.verifiable_key AS
  SELECT id, kid, user_id, public_jwk, signs_until, published_until
  FROM akeys.key
  WHERE state = 'ACTIVE'
    AND now() < published_until;

CREATE VIEW api.signing_key AS
  SELECT id, kid, user_id, session_id, state, public_jwk, created_at, activated_at,
         signs_until, published_until
    FROM akeys.signing_key;
CREATE VIEW api.signing_material AS
  SELECT id, kid, user_id, kms_ref, signs_until
    FROM akeys.signing_material;
CREATE VIEW api.destroyable_key AS
  SELECT id, kid, user_id, kms_ref, signs_until
    FROM akeys.destroyable_key;
CREATE VIEW api.verifiable_key AS
  SELECT id, kid, user_id, public_jwk, signs_until, published_until
    FROM akeys.verifiable_key;

GRANT SELECT ON api.signing_key, api.signing_material,
                api.destroyable_key, api.verifiable_key TO app_admin_plane;

DROP INDEX akeys.uq_key_one_active_per_purpose;

CREATE UNIQUE INDEX uq_key_one_active_per_admin
  ON akeys.key (user_id)
  WHERE state = 'ACTIVE' AND private_destroyed_at IS NULL;

ALTER TABLE akeys.key DROP COLUMN purpose;
DROP TYPE akeys.key_purpose;

RESET ROLE;
