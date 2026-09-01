-- Up Migration

-- Une fonction a besoin de son schéma.
--
-- ═══ CE QUE `the_plane_turns_the_ring` A MANQUÉ ═══
--
-- Elle a accordé EXECUTE sur `audit.ensure_partitions` et `audit.detach_expired`
-- à `app_admin_plane`. Le catalogue le confirmait :
--
--     proacl = {admin_owner=X/admin_owner, app_admin_plane=X/admin_owner}
--     has_function_privilege('app_admin_plane', …, 'EXECUTE') = true
--
-- Et l'appel échouait quand même, en 42501 :
--
--     ERROR:  permission denied for schema audit
--
-- EXECUTE dit ce qu'on a le droit d'appeler ; USAGE dit ce qu'on a le droit de
-- NOMMER. Sans le second, le premier ne se prête à personne : on ne peut pas
-- désigner `audit.detach_expired` sans traverser `audit`. Les deux privilèges se
-- lisent comme un seul et n'en sont pas un, et c'est la raison pour laquelle le
-- premier grant paraissait suffisant — le catalogue répondait « oui » à la
-- question qu'on lui posait.
--
-- ═══ POURQUOI CE N'ÉTAIT PAS VISIBLE AVANT ═══
--
-- Le service appelle des fonctions dans `admin` et `webauthn`, et lit `api`. Ces
-- trois schémas portent USAGE depuis l'amorçage, si bien qu'aucun appel n'avait
-- jamais eu à le réclamer. `akeys` et `audit` ne l'ont jamais eu — le service
-- n'entrait ni dans l'un ni dans l'autre, lisant les clés par `api.*`.
--
-- L'anneau est le premier geste qui oblige le plan à NOMMER quelque chose dans
-- `audit`.
--
-- ═══ CE QUE USAGE N'ACCORDE PAS ═══
--
-- Rien sur les objets. USAGE est le droit de traverser le schéma, pas d'y lire :
-- `audit.event`, `audit.watched`, `audit.retention` gardent leur ACL, et
-- `audit.record` reste inexécutable par le plan — vérifié, `has_function_privilege`
-- rend faux. Le service ne gagne donc que les deux fonctions qu'on lui a nommées.
--
-- Le risque qui resterait est celui qu'`a_default_acl_is_an_open_door` a
-- documenté : une fonction AJOUTÉE plus tard dans `audit` naîtrait exécutable par
-- PUBLIC, donc atteignable dès lors que le schéma se traverse. Ce n'est pas une
-- raison de refuser USAGE — `admin` et `webauthn` vivent avec depuis toujours —
-- mais c'est la raison pour laquelle `TestExecuteIsGrantedToNobodyByDefault`
-- interroge le catalogue en continu plutôt qu'une fois.
--
-- ═══ POURQUOI UNE SECONDE MIGRATION ET NON UNE CORRECTION ═══
--
-- `the_plane_turns_the_ring` est déjà appliquée. Goose la rejoue par version : la
-- corriger sur place laisserait les bases où elle a tourné sans le complément, et
-- rien ne le dirait. La règle du dépôt vaut ici comme ailleurs, et l'erreur
-- mérite d'être écrite plutôt qu'effacée — EXECUTE sans USAGE se retrouvera.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code. Elle n'accorde qu'un privilège.
--   Celui qu'elle FAIT DISPARAÎTRE : 42501 sur les deux fonctions de l'anneau.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

-- SET ROLE, parce que c'est le PROPRIÉTAIRE qui accorde. Sans lui le grant
-- viendrait du compte de migration éphémère d'OpenBao et disparaîtrait avec lui
-- au `DROP OWNED` de la révocation.
SET ROLE admin_owner;

GRANT USAGE ON SCHEMA audit TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

REVOKE USAGE ON SCHEMA audit FROM app_admin_plane;

RESET ROLE;
