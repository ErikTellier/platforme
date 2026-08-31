-- Up Migration

-- UNE APPROBATION N'EST PAS UNE DEMANDE.
--
-- ═══ LE MÊME DÉFAUT QU'`only_a_touch_consumes_a_challenge`, UNE TABLE PLUS LOIN ═══
--
-- Cette migration-là racontait ceci :
--
--     « `api.challenge` a été écrite avant que `scope` et `target_tenant_id`
--       n'existent, et sa liste de colonnes a été figée là. Résultat : le plan ne
--       peut insérer AUCUN défi — pas par politique, par forme de vue. Or
--       l'ouvrir telle quelle rendrait vivant un défaut jusque-là inoffensif. »
--
-- Mot pour mot le cas d'`api.authority_request`. Elle porte `INSERT` AU NIVEAU DE
-- LA TABLE, donc sur toutes ses colonnes — `approved_at` et `approved_by`
-- comprises. Un plan qui peut écrire une demande DÉJÀ APPROUVÉE s'approuve
-- lui-même, et la cérémonie à quatre yeux devient décorative : `four_eyes_are_two_acts`
-- resterait le chemin honnête, et il y en aurait un autre.
--
-- Ce qui l'en empêche aujourd'hui n'est pas une garde. C'est que la vue OMET
-- `request_command_id`, qui est `NOT NULL` sans défaut : toute insertion échoue,
-- quelles que soient les colonnes fournies. La porte est murée, pas fermée — et
-- la débloquer telle quelle ouvrirait les deux à la fois.
--
-- ═══ CE QUE LA VUE ACCORDE DÉSORMAIS, ET CE QU'ELLE REFUSE ═══
--
-- INSERT colonne par colonne, sur ce qu'une DEMANDE porte et rien d'autre :
--
--     scope, tenant_id, subject_user_id, reason, expires_at,
--     requested_by, request_command_id
--
-- Ce qui n'est pas nommé n'est pas écrit :
--
--   `approved_at`, `approved_by`, `approval_command_id`
--       L'approbation est le SECOND acte, par un TROISIÈME. `four_eyes_are_two_acts`
--       le tient déjà — approbateur distinct du demandeur et du sujet — mais un
--       privilège qui laisse poser les trois colonnes à l'insertion laisse
--       fabriquer une demande née approuvée. La contrainte parlerait ; elle ne
--       devrait pas avoir à le faire.
--   `withdrawn_at`, `withdrawn_by`
--       Retirer est un acte, pas un état de naissance. Une demande née retirée
--       n'a jamais attendu personne.
--   `id`, `requested_at`
--       Ont un défaut. Les accorder n'ajoute que la possibilité de les
--       contredire — et une demande antidatée fausserait `pending_request`, qui
--       calcule depuis combien de temps une décision dort.
--
-- AUCUN `UPDATE`. L'approbation viendra, et elle aura son propre grant, sur ses
-- propres colonnes, le jour où la route qui la porte existera. Accorder
-- maintenant ce que rien n'appelle est précisément ce que ce dépôt paie cher.
--
-- ═══ `security_invoker`, POUR LA MÊME RAISON QUE `signed_command` ═══
--
-- `admin.authority_request` porte une sécurité de ligne FORCÉE, et `tenant_visible`
-- appelle `admin.may_read(tenant_id)`. Sans `security_invoker`, la vue jugerait
-- sous l'identité de son propriétaire au lieu de celle de l'appelant. La vue
-- précédente ne l'avait pas — en lecture seule utile, la politique s'évaluait
-- pour `admin_owner`, ce qui rendait `tenant_visible` sans effet.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau.
--
--   Les codes qu'elle rend ATTEIGNABLES, faute d'un chemin pour les déclencher :
--     AD088  la commande de demande n'est pas celle-ci, ou pas de ce demandeur
--     AD089  l'approbation ne correspond pas à cette demande
--     42501  approuver à l'insertion — le privilège parle avant la contrainte
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- DÉTRUIRE PUIS RECRÉER, et ce n'est pas un raccourci. On ne retire pas une
-- colonne d'un privilège accordé au niveau de la table : `REVOKE INSERT (col)`
-- ne fait rien d'utile, le privilège de table subsiste et continue de couvrir la
-- colonne. PostgreSQL n'échoue pas, il ne retire simplement rien — le pire des
-- deux, puisque la migration paraît avoir réussi. Les privilèges meurent avec
-- l'objet ; c'est la seule façon sûre de repartir d'une liste explicite.
DROP VIEW api.authority_request;

CREATE VIEW api.authority_request
    WITH (security_invoker = TRUE)
AS
SELECT id, scope, tenant_id, subject_user_id, reason, expires_at,
       requested_at, requested_by, request_command_id,
       approved_at, approved_by, approval_command_id,
       withdrawn_at, withdrawn_by
  FROM admin.authority_request;

COMMENT ON VIEW api.authority_request IS
'Les demandes d''autorité, telles que le plan peut les voir et les poser. Il peut
en DEMANDER une — portée, client, sujet, motif, échéance, demandeur, et la
commande signée qui la porte — et jamais déclarer qu''elle a été approuvée ni
retirée : ces colonnes ne sont pas accordées à l''écriture. Une demande née
approuvée serait une auto-approbation, et la cérémonie à quatre yeux ne serait
plus qu''un chemin parmi deux.';

GRANT SELECT ON api.authority_request TO app_admin_plane;

-- COLONNE PAR COLONNE. Ce qui n'est pas nommé n'est pas écrit.
GRANT INSERT (scope, tenant_id, subject_user_id, reason, expires_at,
              requested_by, request_command_id)
    ON api.authority_request TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP VIEW api.authority_request;

-- La vue d'origine, telle qu'elle était : sans `request_command_id`, donc
-- inutilisable à l'insertion, et avec l'INSERT de table qui couvrait
-- l'approbation. On restitue l'état exact, défaut compris — une annulation qui
-- corrigerait au passage ne serait pas une annulation.
CREATE VIEW api.authority_request AS
SELECT id, scope, tenant_id, subject_user_id, reason, expires_at,
       requested_at, requested_by,
       approved_at, approved_by, withdrawn_at, withdrawn_by
  FROM admin.authority_request;

GRANT SELECT, INSERT ON api.authority_request TO app_admin_plane;

RESET ROLE;
