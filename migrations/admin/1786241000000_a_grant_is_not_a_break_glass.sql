-- Up Migration

-- UN OCTROI N'EST PAS UNE ÉCHAPPATOIRE.
--
-- ═══ LA CÉRÉMONIE S'ARRÊTAIT AU DEUXIÈME ACTE ═══
--
-- `four_eyes_are_two_acts` a écrit la demande, `an_approval_is_not_a_request`
-- l'a ouverte à l'inscription, `only_the_outcome_of_a_request_is_written` a
-- ouvert l'approbation. Trois migrations pour deux actes, et le troisième —
-- CELUI QUI ACCORDE — n'avait aucun chemin.
--
-- `admin.platform_admin` et `admin.admin_tenant` n'ont jamais eu de vue `api`.
-- Le plan pouvait donc faire approuver une demande et rien de plus : la file
-- avait une sortie, et cette sortie ne donnait sur rien. C'est exactement ce
-- que le commentaire de `withdrawn_at` décrit — « l'endroit où les décisions
-- vont mourir, et où l'on finit par contourner la règle plutôt que de
-- l'appliquer ».
--
-- ═══ CE QUE LA VUE ACCORDE, ET CE QU'ELLE REFUSE ═══
--
-- INSERT colonne par colonne, sur ce qu'un OCTROI porte et rien d'autre :
--
--     user_id, granted_by, reason, expires_at, approved_by,
--     command_id, request_id
--
-- Ce qui n'est pas nommé n'est pas écrit :
--
--   `break_glass`
--       C'EST LA COLONNE QUI COMPTE ICI. `authority_grant_guard` la lit en
--       premier : posée, elle rend la main avant tout contrôle de second
--       approbateur, et `grant_follows_a_request` fait de même — « IF
--       NEW.break_glass THEN RETURN NEW ». Aucune contrainte ne la borne, et
--       `authority_scope` l'autorise sur PLATFORM. Un plan qui pourrait
--       l'écrire s'accorderait donc l'autorité la plus haute de la plateforme
--       SANS demande, SANS approbateur et SANS second regard — la cérémonie
--       resterait le chemin honnête, et il y en aurait un autre. C'est
--       littéralement la promesse faite au client qui tomberait.
--
--       L'échappatoire reste ce qu'elle doit être : un geste hors du plan,
--       posé par quelqu'un qui a la main sur la base, pas une case qu'une
--       route peut cocher.
--
--   `granted_at`
--       A un défaut, et `authority_grant_guard` MESURE le terme à partir de
--       lui : `NEW.expires_at - NEW.granted_at > pol.max_duration` (AD073).
--       Un plan qui date son propre octroi choisit donc le terme que la garde
--       croit voir — le poser dans l'avenir rétrécit la durée apparente sans
--       rien changer à la durée réelle, puisque `is_platform_admin` ne regarde
--       que `revoked_at` et `expires_at`, jamais `granted_at`.
--
--       Mesuré avant d'écrire : `max_duration` est nulle pour les deux portées
--       aujourd'hui, donc AD073 ne mord pas et le contournement ne vaut rien.
--       C'est précisément pour ça qu'on ferme maintenant : le jour où
--       quelqu'un pose un plafond, il le croira opposable.
--
--   `id`
--       A un défaut. L'accorder n'ajoute que la possibilité de le contredire,
--       et un identifiant choisi par l'appelant est un identifiant qu'on peut
--       faire collisionner. Même mot que dans `only_the_base_dates_a_command`.
--
--   `revoked_at`, `revoked_by`, `revoked_command_id`
--       Révoquer est un acte, pas un état de naissance — et il a sa propre
--       action au vocabulaire (`authority.revoke`), donc sa propre commande
--       signée et sa propre route, le jour où elle existera. Une autorité née
--       révoquée est un fait qui n'a jamais eu lieu.
--
-- ═══ POURQUOI DEUX VUES ET NON UNE ═══
--
-- Parce que ce sont deux tables, et `tenant_scoped_admins` a dit pourquoi :
-- « être global est une ligne que quelqu'un a créée, avec un motif et une date,
-- pas une colonne que quelqu'un a oubliée de remplir ».
--
-- Elles ne portent d'ailleurs pas les mêmes colonnes. `request_id` n'existe que
-- sur `platform_admin` : `four_eyes_are_two_acts` ne l'a ajoutée que là, parce
-- que seule la portée PLATFORM exige un second approbateur. Exposer TENANT
-- quand même n'est pas de la symétrie décorative — une demande de portée TENANT
-- s'inscrit et s'approuve déjà, et sans cette vue elle finirait exactement dans
-- la file sans sortie qu'on vient de refermer pour PLATFORM.
--
-- ═══ POURQUOI `security_invoker` ═══
--
-- `admin.admin_tenant` porte une sécurité de ligne FORCÉE et deux politiques,
-- dont `tenant_visible` qui appelle `admin.may_read(tenant_id)`. Sans
-- `security_invoker`, la vue s'exécuterait sous l'identité de son propriétaire
-- et jugerait pour quelqu'un d'autre que l'appelant.
--
-- `admin.platform_admin` n'a PAS de sécurité de ligne — l'autorité de
-- plateforme ne se cloisonne par rien, il n'y a pas de juridiction à opposer.
-- Sa vue est en `security_invoker` quand même : les privilèges doivent se juger
-- sur l'appelant, et une vue du même schéma qui se lirait autrement serait la
-- seule exception à retenir.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Elle expose deux tables et borne ce qu'on peut y
--   écrire.
--
--   Les codes qu'elle rend ATTEIGNABLES, faute d'un chemin pour les déclencher :
--     AD070  l'administrateur visé est désactivé
--     AD073  le plafond de durée de la portée
--     AD074  une autorité ne s'accorde pas à soi-même
--     AD084  une autorité s'accorde par une commande signée
--     AD085  la commande dépensée n'est pas un octroi de CE signataire
--     AD086  la portée PLATFORM exige une demande APPROUVÉE
--     AD100  aucun administrateur n'est lié à cette session
--     23505  `platform_admin_one_live` / `admin_tenant_one_live` : une seule
--            autorité vivante par administrateur, et par client
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE VIEW api.platform_admin
    WITH (security_invoker = TRUE)
AS
SELECT id, user_id, granted_at, granted_by, reason,
       revoked_at, revoked_by, revoked_command_id,
       expires_at, approved_by, break_glass, command_id, request_id
  FROM admin.platform_admin;

COMMENT ON VIEW api.platform_admin IS
'L''autorité de plateforme, telle que le plan peut la voir et l''accorder. Il
peut en ÉCRIRE une — le sujet, le signataire, le motif, le terme, l''approbateur,
la commande signée et la demande approuvée qu''elle dénoue — et jamais ni la
DATER, ni la nommer, ni la faire naître révoquée, ni cocher `break_glass`.

Cette dernière est celle qui compte : posée, elle rend la main avant tout
contrôle de second approbateur, et le plan s''accorderait alors l''autorité la
plus haute sans que personne ne l''ait approuvée.';

GRANT SELECT ON api.platform_admin TO app_admin_plane;

-- COLONNE PAR COLONNE, ET DÈS LE DÉPART. Un GRANT de table serait irréversible
-- au niveau de la colonne — `only_a_touch_consumes_a_challenge` l'a mesuré :
-- « REVOKE INSERT (col) ne fait rien d'utile, PostgreSQL n'échoue pas, il ne
-- retire simplement rien ». Il faudrait le révoquer en entier pour le refaire.
GRANT INSERT (user_id, granted_by, reason, expires_at,
              approved_by, command_id, request_id)
    ON api.platform_admin TO app_admin_plane;

CREATE VIEW api.admin_tenant
    WITH (security_invoker = TRUE)
AS
SELECT id, user_id, tenant_id, granted_at, granted_by, reason,
       revoked_at, revoked_by, revoked_command_id,
       expires_at, approved_by, break_glass, command_id
  FROM admin.admin_tenant;

COMMENT ON VIEW api.admin_tenant IS
'L''autorité sur un client, telle que le plan peut la voir et l''accorder. Mêmes
refus que `api.platform_admin` : ni date, ni identifiant, ni révocation de
naissance, ni `break_glass`.

Pas de `request_id` non plus, mais parce que la colonne n''existe pas — la portée
TENANT n''exige pas de second approbateur, et `grant_follows_a_request` n''est
attachée qu''à `platform_admin`. Une demande de portée TENANT s''inscrit et
s''approuve quand même ; c''est par ici qu''elle aboutit.';

GRANT SELECT ON api.admin_tenant TO app_admin_plane;

GRANT INSERT (user_id, tenant_id, granted_by, reason, expires_at,
              approved_by, command_id)
    ON api.admin_tenant TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP VIEW api.admin_tenant;
DROP VIEW api.platform_admin;

RESET ROLE;
