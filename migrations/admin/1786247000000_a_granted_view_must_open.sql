-- Up Migration

-- UNE VUE ACCORDÉE DOIT S'OUVRIR.
--
-- ═══ CE QUI A ÉTÉ CONSTATÉ ═══
--
-- Dix-huit vues d'`api` étaient accordées à `app_admin_plane` et renvoyaient
-- `42501` à chaque appel. Un tiers de la surface de lecture. Elles figurent
-- dans un `\dv`, elles ont leur `GRANT`, et elles ne s'ouvrent pas.
--
-- La cause tient en une ligne : ces vues portent `security_invoker = true`,
-- donc elles s'exécutent avec les droits de L'APPELANT — qui doit alors pouvoir
-- lire les tables du dessous. Il ne le pouvait pas.
--
-- Personne ne s'en était aperçu parce que PERSONNE NE S'ÉTAIT JAMAIS CONNECTÉ
-- comme `app_admin_plane`. Les bancs tournaient en superutilisateur, qui
-- contourne le RLS et possède tout. La même cause racine que les douze
-- politiques de sécurité de ligne que rien n'éprouvait.
--
-- ═══ LA RÈGLE APPLIQUÉE ═══
--
-- Deux familles, et la frontière est celle du CYCLE DE VIE :
--
--   Une table dont l'écriture et la consommation passent par des fonctions
--   `SECURITY DEFINER` dédiées n'a pas à être lue directement. La vue est
--   l'octroi de trop : on le RETIRE.
--
--   Une table sans fonction d'accès est une donnée que le plan doit lire. C'est
--   le droit qui manque : on l'OUVRE.
--
-- ═══ CE QU'ON FERME, ET POURQUOI ═══
--
--   api.login_flow        `open_login_flow`, `consume_login_flow`, `purge_`
--   api.spent_proof       `spend_proof`, `purge_spent_proofs`
--   api.enrollment_ticket `issue_`, `consume_`, `ticket_is_open`, `purge_`
--   api.retention         `purge_challenges`, `purge_login_flows`, `purge_`
--
-- `api.login_flow` MÉRITE D'ÊTRE NOMMÉE SÉPARÉMENT : elle exposait
-- `code_verifier` — le secret PKCE qui prouve que celui qui échange le code est
-- celui qui l'a demandé — et `state`, le jeton anti-CSRF. Les lire permet de
-- terminer l'authentification de quelqu'un d'autre. Ce n'était pas un octroi
-- oublié, c'était un octroi de trop, et le fait qu'il n'ait jamais fonctionné
-- est la seule raison pour laquelle il n'a rien coûté.
--
-- ═══ CE QU'ON OUVRE ═══
--
--   akeys.key                 par `signing_key`, `verifiable_key`,
--                             `signing_material`, `destroyable_key` — émettre
--                             et valider un jeton passe par là
--   admin."user"              par `user`, `active_user`
--   admin.command_batch       par `command_batch`, `batch_estate`,
--                             `batch_incomplete`
--   admin.residency_region    par `residency_region`, `residency_map`
--   admin.command_action      vocabulaire
--   admin.identity_provider   vocabulaire
--   admin.session_end_reason  vocabulaire
--
-- ═══ ET UNE CORRECTION QUE L'OUVERTURE A RENDUE NÉCESSAIRE ═══
--
-- `admin.command_batch` PORTE `target_tenant_id` ET N'AVAIT AUCUN RLS.
--
-- L'ouvrir telle quelle aurait rendu lisible à tout administrateur le lot de
-- commandes de n'importe quel client : l'empreinte du manifeste, le nombre de
-- gestes déclarés, qui les a signés et quand. Exactement la fuite que
-- `tenant_visible` ferme sur `signed_command`, sa jumelle — un lot n'est qu'un
-- regroupement de commandes signées, et il doit se cacher comme elles.
--
-- La table reçoit donc les deux politiques de ses pairs AVANT son octroi. Une
-- ouverture qui creuse un trou n'est pas une ouverture.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   aucun — droits et politiques uniquement
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout      = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- ─────────────────────────────────────────────────────────────────────────
-- 1. CE QUI SE FERME
-- ─────────────────────────────────────────────────────────────────────────

REVOKE ALL ON api.login_flow        FROM app_admin_plane;
REVOKE ALL ON api.spent_proof       FROM app_admin_plane;
REVOKE ALL ON api.enrollment_ticket FROM app_admin_plane;
REVOKE ALL ON api.retention         FROM app_admin_plane;

-- ─────────────────────────────────────────────────────────────────────────
-- 2. LE LOT DE COMMANDES SE CLOISONNE COMME LES COMMANDES
--
-- `FORCE` et non seulement `ENABLE` : sans lui, le PROPRIÉTAIRE de la table
-- échappe à ses propres politiques, et toutes les fonctions `SECURITY DEFINER`
-- s'exécutent comme lui. La politique deviendrait décorative pour le seul rôle
-- qui compte.
-- ─────────────────────────────────────────────────────────────────────────

ALTER TABLE admin.command_batch ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin.command_batch FORCE  ROW LEVEL SECURITY;

-- Le laissez-passer du propriétaire, sans lequel les fonctions vérifiées
-- deviennent aveugles — `command_belongs_to_its_batch` la lit à chaque commande
-- de lot.
CREATE POLICY owner_is_the_vetted_path ON admin.command_batch
    AS PERMISSIVE FOR ALL TO admin_owner
    USING (true) WITH CHECK (true);

-- Et la même lecture que `signed_command`, au mot près.
CREATE POLICY tenant_visible ON admin.command_batch
    AS PERMISSIVE FOR ALL TO app_admin_plane
    USING (admin.may_read(target_tenant_id))
    WITH CHECK (admin.may_read(target_tenant_id));

-- ═══ POSER UNE POLITIQUE FAIT ENTRER DES VUES DANS SON PÉRIMÈTRE ═══
--
-- `api.command_batch` n'avait pas `security_invoker` — et n'en avait pas
-- besoin tant que sa table n'était pas protégée. Deux lignes plus haut, elle en
-- a besoin : sans l'option, la vue s'exécute comme SON PROPRIÉTAIRE, à qui
-- `owner_is_the_vetted_path` rend `true` sans condition. Elle rendrait donc
-- tous les lots de tous les clients, et le `tenant_visible` qu'on vient
-- d'écrire ne servirait à rien.
--
-- La première assertion de `doctrine.sql` l'a dit dans la seconde qui a suivi
-- l'application de cette migration. C'était sa raison d'être, et c'est la
-- deuxième fois qu'elle attrape ce cas.
--
-- SES TROIS SŒURS L'AVAIENT DÉJÀ : `admin.batch_estate`,
-- `admin.batch_incomplete` et leurs ré-exports. Seule celle-ci manquait.
--
-- `ALTER VIEW ... SET` ET NON `CREATE OR REPLACE VIEW` : le second
-- RÉINITIALISE les options au lieu de les conserver, ce qui est précisément
-- comment vingt-six vues avaient perdu l'option en silence.
ALTER VIEW api.command_batch SET (security_invoker = true);

-- ─────────────────────────────────────────────────────────────────────────
-- 3. CE QUI S'OUVRE
--
-- `USAGE` SUR LE SCHÉMA D'ABORD : sans lui, un `GRANT SELECT` sur la table ne
-- sert à rien — le schéma reste fermé, et l'erreur parle du schéma, pas de la
-- table. C'est ce qui rendait `api.signing_key` incompréhensible.
--
-- SELECT SEULEMENT. Les clés s'écrivent par les fonctions du plan d'émission,
-- jamais par le plan d'administration.
-- ─────────────────────────────────────────────────────────────────────────

GRANT USAGE  ON SCHEMA akeys TO app_admin_plane;
GRANT SELECT ON akeys.key    TO app_admin_plane;

-- `admin."user"` reste sans RLS, et c'est délibéré : un administrateur doit
-- pouvoir désigner un COLLÈGUE comme sujet d'une demande d'autorité. La table
-- ne porte que des identifiants, une date de création et une désactivation —
-- aucune donnée de client.
GRANT SELECT ON admin."user"      TO app_admin_plane;
GRANT SELECT ON admin.command_batch TO app_admin_plane;

-- Les vocabulaires. Sans eux, le plan ne peut pas afficher le libellé d'une
-- action, ni proposer une région, ni nommer la raison de fin d'une session.
GRANT SELECT ON admin.residency_region   TO app_admin_plane;
GRANT SELECT ON admin.command_action     TO app_admin_plane;
GRANT SELECT ON admin.identity_provider  TO app_admin_plane;
GRANT SELECT ON admin.session_end_reason TO app_admin_plane;

-- ─────────────────────────────────────────────────────────────────────────
-- 4. LA COUCHE QU'ON N'AVAIT PAS VUE
--
-- `api.signing_key` NE LIT PAS `akeys.key`. Elle lit `akeys.signing_key`, qui
-- lit `akeys.key`. Le schéma `api` ré-exporte des vues INTERNES, et treize des
-- dix-huit vues murées l'étaient à cause de ce maillon-là, pas de la table.
--
--   api.signing_key  →  akeys.signing_key  →  akeys.key
--
-- `security_invoker` exige les droits sur TOUTE la chaîne, pas seulement aux
-- deux bouts. Une première version de cette migration ouvrait les tables et
-- s'arrêtait là : les douze mêmes vues rendaient toujours `42501`, et le
-- message parlait d'une « view », pas d'une table. C'est ce mot qui a mis sur
-- la piste.
--
-- CE N'EST PAS UNE BRÈCHE DANS LA COUCHE `api`. Ces vues internes tombent sous
-- les mêmes politiques que leurs tables — `own_or_platform` pour les clés,
-- `tenant_visible` pour les lots. Le schéma `api` est une frontière de CONTRAT,
-- qui protège l'appelant d'un changement de forme ; ce n'est pas une frontière
-- de droits, et `doctrine.sql` ne lui a jamais demandé de l'être.
-- ─────────────────────────────────────────────────────────────────────────

GRANT SELECT ON admin.active_user             TO app_admin_plane;
GRANT SELECT ON admin.batch_estate            TO app_admin_plane;
GRANT SELECT ON admin.batch_incomplete        TO app_admin_plane;
GRANT SELECT ON admin.live_pair               TO app_admin_plane;
GRANT SELECT ON admin.live_session            TO app_admin_plane;
GRANT SELECT ON admin.pending_request         TO app_admin_plane;
GRANT SELECT ON admin.residency_map           TO app_admin_plane;
GRANT SELECT ON admin.tenant_without_residency TO app_admin_plane;
GRANT SELECT ON admin.unbound_session         TO app_admin_plane;

GRANT SELECT ON akeys.destroyable_key  TO app_admin_plane;
GRANT SELECT ON akeys.signing_key      TO app_admin_plane;
GRANT SELECT ON akeys.signing_material TO app_admin_plane;
GRANT SELECT ON akeys.verifiable_key   TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET LOCAL lock_timeout      = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- CE RETOUR REND LE SCHÉMA EXACTEMENT COMME IL ÉTAIT, trous compris. Ce n'est
-- pas un aveu : un retour qui « améliore » n'est plus un retour, et on ne
-- saurait plus quel état on restaure.
REVOKE SELECT ON akeys.verifiable_key   FROM app_admin_plane;
REVOKE SELECT ON akeys.signing_material FROM app_admin_plane;
REVOKE SELECT ON akeys.signing_key      FROM app_admin_plane;
REVOKE SELECT ON akeys.destroyable_key  FROM app_admin_plane;

REVOKE SELECT ON admin.unbound_session         FROM app_admin_plane;
REVOKE SELECT ON admin.tenant_without_residency FROM app_admin_plane;
REVOKE SELECT ON admin.residency_map           FROM app_admin_plane;
REVOKE SELECT ON admin.pending_request         FROM app_admin_plane;
REVOKE SELECT ON admin.live_session            FROM app_admin_plane;
REVOKE SELECT ON admin.live_pair               FROM app_admin_plane;
REVOKE SELECT ON admin.batch_incomplete        FROM app_admin_plane;
REVOKE SELECT ON admin.batch_estate            FROM app_admin_plane;
REVOKE SELECT ON admin.active_user             FROM app_admin_plane;

REVOKE SELECT ON admin.session_end_reason FROM app_admin_plane;
REVOKE SELECT ON admin.identity_provider  FROM app_admin_plane;
REVOKE SELECT ON admin.command_action     FROM app_admin_plane;
REVOKE SELECT ON admin.residency_region   FROM app_admin_plane;
REVOKE SELECT ON admin.command_batch      FROM app_admin_plane;
REVOKE SELECT ON admin."user"             FROM app_admin_plane;
REVOKE SELECT ON akeys.key                FROM app_admin_plane;
REVOKE USAGE  ON SCHEMA akeys             FROM app_admin_plane;

-- La table redevient sans RLS, donc la vue sort du périmètre et n'a plus
-- besoin de l'option. `RESET` la retire, ce qui rend l'état d'avant — un
-- retour qui laisserait l'option en place ne serait pas un retour.
ALTER VIEW api.command_batch RESET (security_invoker);

DROP POLICY tenant_visible           ON admin.command_batch;
DROP POLICY owner_is_the_vetted_path ON admin.command_batch;
ALTER TABLE admin.command_batch NO FORCE ROW LEVEL SECURITY;
ALTER TABLE admin.command_batch DISABLE  ROW LEVEL SECURITY;

-- LES QUATRE OCTROIS QU'ON AVAIT RETIRÉS REVIENNENT. `initial_schema` les
-- posait ; c'est à ce retour de les rendre, puisque c'est lui qui les a ôtés.
-- Ils rouvrent `api.login_flow`, donc le vérificateur PKCE — raison de plus
-- pour que ce retour ne serve qu'à revenir en arrière.
GRANT SELECT ON api.login_flow        TO app_admin_plane;
GRANT SELECT ON api.spent_proof       TO app_admin_plane;
GRANT SELECT ON api.enrollment_ticket TO app_admin_plane;
GRANT SELECT ON api.retention         TO app_admin_plane;

RESET ROLE;
