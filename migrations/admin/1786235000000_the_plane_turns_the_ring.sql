-- Up Migration

-- Le plan tourne l'anneau lui-même.
--
-- ═══ L'ANNEAU EXISTAIT, PERSONNE NE LE TOURNAIT ═══
--
-- `the_log_is_a_ring` a écrit les deux gestes qui le referment : `ensure_partitions()`
-- ouvre devant, `detach_expired()` ferme derrière. Vingt-quatre mois attachés, ce
-- que NIS2 réclame.
--
-- Aucun des deux n'avait d'appelant. `ensure_partitions(12)` tourne EXACTEMENT UNE
-- FOIS, à la fin de `audit_schema`, qui sème douze mois. `detach_expired()` n'est
-- appelée par rien du tout — ni par le service, ni par un script, ni par un test
-- d'exploitation. L'anneau était une mécanique complète sans main dessus.
--
-- ═══ CE QUE ÇA COÛTAIT, ET QUAND ═══
--
-- Douze mois semés en août 2026, donc rien à signaler jusqu'à l'été 2027. Passé ce
-- terme, les événements tombent dans `audit.event_overflow` — la partition par
-- défaut — et c'est là que ça devient grave, parce que la panne se REFERME sur
-- elle-même :
--
--   1. `ensure_partitions` n'a pas tourné, donc le mois n'a pas de partition ;
--   2. les lignes du mois vont dans la partition par défaut ;
--   3. et une partition par défaut qui contient des lignes d'un mois EMPÊCHE de
--      provisionner ce mois-là — Postgres refuse, « updated partition constraint
--      for default partition would be violated by some row ».
--
-- Le commentaire d'`audit.unpartitioned` le dit déjà, et précise « mesuré, pas
-- supposé ». À partir de l'étape 3, on ne rattrape plus en appelant la fonction :
-- il faut sortir les lignes à la main d'abord. Ces événements-là échappent alors à
-- l'anneau pour toujours — jamais détachés, donc jamais archivés, donc éternels.
--
-- ═══ POURQUOI UN SIMPLE GRANT, ET RIEN D'AUTRE ═══
--
-- Les deux fonctions sont écrites, éprouvées, et correctes. Il ne leur manquait
-- que le droit d'être appelées : `public_execute_is_closed` puis
-- `a_default_acl_is_an_open_door` ont fermé EXECUTE à PUBLIC sur tout le schéma,
-- à juste titre — mais personne n'a ensuite ouvert ce qu'un appelant légitime
-- devait pouvoir faire. Vérifié sur la base vivante : `app_admin_plane` ne pouvait
-- exécuter ni l'une ni l'autre.
--
-- `detach_expired` est SECURITY DEFINER et tourne donc sous `admin_owner`, qui
-- possède les partitions. C'est ce qui rend le droit sûr à accorder : l'appelant
-- ne gagne pas de pouvoir sur les tables, il gagne le droit de DEMANDER un geste
-- que la fonction borne elle-même — `per_call`, trois mois par appel.
--
-- ═══ CE QUE CE GRANT N'ACCORDE PAS ═══
--
-- Détacher n'est pas supprimer. Une partition détachée reste une table, avec ses
-- lignes : « tant qu'une ligne figure ici, rien n'a été perdu ». L'export puis la
-- destruction appartiennent à qui a décidé de la politique, et ce droit-ci ne les
-- donne pas.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Elle n'accorde qu'un privilège.
--
--   Rappel de celui qu'elle rend ATTEIGNABLE, puisqu'il ne l'était par personne :
--     XA020  detach_expired : aucune fenêtre de rétention déclarée pour le
--            journal. Fermé et bruyant, délibérément — le silence signifierait
--            « la rétention ne tourne plus » sans que personne ne l'apprenne.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

-- SET ROLE, parce que c'est le PROPRIÉTAIRE qui accorde. Sans lui le grant
-- viendrait du compte de migration éphémère d'OpenBao, et disparaîtrait avec lui
-- au `DROP OWNED` de la révocation — un droit qui s'évapore à la rotation
-- suivante est pire qu'un droit absent, parce qu'il a fonctionné une fois.
SET ROLE admin_owner;

GRANT EXECUTE ON FUNCTION audit.ensure_partitions(int) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION audit.detach_expired()       TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

REVOKE EXECUTE ON FUNCTION audit.ensure_partitions(int) FROM app_admin_plane;
REVOKE EXECUTE ON FUNCTION audit.detach_expired()       FROM app_admin_plane;

RESET ROLE;
