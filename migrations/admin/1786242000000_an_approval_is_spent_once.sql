-- Up Migration

-- UNE APPROBATION SE DÉPENSE UNE FOIS.
--
-- ═══ CE QUE `a_grant_is_not_a_break_glass` A RENDU ATTEIGNABLE ═══
--
-- La migration précédente a ouvert le troisième acte : le plan peut enfin
-- écrire l'autorité qu'une demande approuvée décrit. Elle a du même coup rendu
-- joignable un trou qui dormait dans le schéma depuis `four_eyes_are_two_acts`.
--
-- `grant_follows_a_request` vérifie que la demande citée est approuvée, non
-- retirée, et qu'elle décrit exactement cet octroi. Elle ne vérifie NULLE PART
-- que cette demande n'a pas déjà servi. Et rien d'autre ne le faisait :
--
--     platform_admin_pk         (id)
--     platform_admin_one_live   (user_id) WHERE revoked_at IS NULL
--     ix_platform_admin_live    (user_id, expires_at) WHERE revoked_at IS NULL
--     ix_platform_admin_break_glass (granted_at) WHERE break_glass
--
-- Aucun ne mentionne `request_id`. Le seul empêchement était donc l'unicité de
-- l'autorité VIVANTE — c'est-à-dire aucun empêchement du tout dès que la
-- première est révoquée :
--
--   1. une demande est approuvée par un tiers, une fois ;
--   2. l'autorité est accordée ;
--   3. elle est révoquée — le geste normal, prévu, tracé ;
--   4. la MÊME demande est accordée de nouveau, et personne n'a regardé.
--
-- Le second regard portait alors sur le premier octroi seulement, et couvrait
-- tous les suivants. C'est exactement ce que `the_genesis_escape` refuse par
-- ailleurs : « révoquer le dernier administrateur dispenserait le suivant de
-- toute cérémonie, et reprendre une autorité deviendrait le moyen le plus
-- simple d'en accorder une sans second regard ». La même phrase vaut ici, une
-- table plus loin.
--
-- ═══ SANS `WHERE revoked_at IS NULL`, ET C'EST TOUT LE POINT ═══
--
-- L'index de vivacité est partiel parce qu'une autorité révoquée doit pouvoir
-- être réaccordée. Celui-ci ne l'est PAS : une demande révoquée reste dépensée.
-- Reprendre une autorité et la vouloir de nouveau, c'est demander de nouveau —
-- et c'est le seul sens que puisse avoir « approuvée par un tiers ».
--
-- ═══ POURQUOI PARTIEL SUR `request_id IS NOT NULL` ═══
--
-- Deux octrois légitimes n'en citent aucune, et ils doivent rester possibles :
--
--   la GENÈSE  — `authority_is_signed` et `grant_follows_a_request` rendent la
--                main quand `platform_admin` est vide. Une seule fois dans la
--                vie de la base, mais cette fois-là compte.
--   le BREAK-GLASS — `authority_scope.allows_break_glass` l'ouvre à PLATFORM.
--                Il ne passe pas par le plan — `a_grant_is_not_a_break_glass`
--                a refusé la colonne à la vue — mais il existe, et un index
--                total le rendrait unique, donc jouable une seule fois.
--
-- Sans la clause, PostgreSQL traiterait d'ailleurs chaque NULL comme distinct
-- et l'index passerait quand même : elle est là pour DIRE que ces deux cas sont
-- prévus, pas pour changer le comportement. Un lecteur qui trouve un index
-- total sur une colonne nullable doit se demander si l'auteur y a pensé.
--
-- ═══ RIEN POUR `admin_tenant` ═══
--
-- Elle n'a pas de `request_id` : `four_eyes_are_two_acts` ne l'a ajoutée qu'à
-- `platform_admin`, parce que seule la portée PLATFORM exige un second
-- approbateur. Il n'y a donc pas d'approbation à dépenser deux fois.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   23505  `platform_admin_one_grant_per_request` : cette demande a déjà été
--          accordée. Le refus est un code standard et non un SQLSTATE propre,
--          parce que c'est une unicité et que le nom de la contrainte dit déjà
--          laquelle a parlé — `db.Contrainte` dans un test.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE UNIQUE INDEX platform_admin_one_grant_per_request
    ON admin.platform_admin (request_id) WHERE request_id IS NOT NULL;

COMMENT ON INDEX admin.platform_admin_one_grant_per_request IS
'Une demande approuvée n''accorde qu''une autorité, et une seule fois.

NON partiel sur `revoked_at`, contrairement à `platform_admin_one_live` : une
autorité révoquée ne libère pas sa demande. Sans quoi accorder, révoquer, puis
accorder de nouveau ferait porter un unique second regard sur une suite
d''octrois — et la cérémonie ne vaudrait que pour le premier.';

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP INDEX admin.platform_admin_one_grant_per_request;

RESET ROLE;
