-- Up Migration

-- REPRENDRE UNE AUTORITÉ LAISSE AUTANT DE PREUVE QUE L'ACCORDER.
--
-- ═══ L'ASYMÉTRIE QUE `a_grant_is_not_a_break_glass` A CRÉÉE ═══
--
-- Depuis cette migration-là, accorder une autorité passe par le plan, cite une
-- commande signée, et se démontre. La REPRENDRE, non : aucune vue `api` ne
-- portait d'`UPDATE`, et le seul chemin restant était `scripts/revoke`, qui
-- écrit dans les tables en direct — donc hors du plan, hors du journal des
-- commandes, et sans qu'aucune touche matérielle n'ait été donnée.
--
-- Le résultat se lit mal dans les deux sens :
--
--   « qui a accordé cette autorité »  →  une commande signée, un défi consommé,
--                                        un administrateur nommé.
--   « qui l'a reprise »               →  une date, un nom, et rien derrière.
--
-- Or reprendre est le geste le plus sensible des deux quand il est ABUSIF :
-- couper l'autorité de celui qui allait s'opposer à quelque chose est
-- exactement ce qu'un journal doit pouvoir montrer. La non-répudiation ne vaut
-- que si elle couvre les deux sens du même acte.
--
-- ═══ LA BASE SAVAIT DÉJÀ TOUT FAIRE ═══
--
-- Rien à écrire côté gardes, et c'est ce qui rend cette migration courte :
--
--   `authority_is_signed('…','REVOKE')`   exige que `revoked_command_id` soit
--       une commande `authority.revoke`, de cette portée, de ce client, et
--       SIGNÉE PAR CELUI QUI EST NOMMÉ comme révoquant (AD084, AD085).
--   `signer_has_authority('…','REVOKE')`  exige que le révocateur détienne
--       lui-même une autorité VIVANTE sur ce périmètre (AD079). Une autorité
--       périmée ou déjà reprise ne reprend rien.
--   `authority_revocation_only`           refuse qu'autre chose bouge (AD072),
--       et qu'on révoque deux fois (AD072). Le terme reste scellé (AD077).
--
-- Ces trois-là attendaient depuis `authority_is_signed`. Il leur manquait un
-- appelant, et deux privilèges pour qu'il existe.
--
-- ═══ LES DEUX PRIVILÈGES, ET POURQUOI DEUX ═══
--
-- `revoked_at` et `revoked_by` portent déjà un `UPDATE` de COLONNE sur les
-- tables depuis `tenant_scoped_admins`. `revoked_command_id` est arrivée plus
-- tard, avec `authority_is_signed`, et personne ne l'a accordée — elle
-- n'existait au plan qu'à l'INSERT, où le GRANT de table la couvre par accident.
--
-- Il faut donc l'ajouter à la table ET accorder les trois sur la vue : celle-ci
-- est en `security_invoker`, donc les deux niveaux se vérifient. C'est ce qui
-- fait qu'une révocation ne peut pas être écrite sans citer sa commande — le
-- privilège s'arrête aux trois colonnes, et la garde exige la troisième.
--
-- ═══ CE QUI N'EST TOUJOURS PAS ACCORDÉ ═══
--
-- Tout le reste. `granted_at`, `granted_by`, `reason`, `expires_at`,
-- `approved_by`, `break_glass`, `request_id`, `command_id` : une révocation
-- n'est pas une correction. `authority_revocation_only` le refuserait de toute
-- façon, et le privilège le dit avant lui — en nommant ce qu'on n'a pas le
-- droit d'écrire plutôt qu'une incohérence qu'on croirait réparable.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Elle rend ATTEIGNABLES, faute d'un chemin :
--     AD072  cette autorité est déjà reprise, ou autre chose que la reprise
--            a été écrit
--     AD077  le terme d'un octroi est scellé — reprendre puis réaccorder
--     AD079  le révocateur ne détient aucune autorité sur ce périmètre
--     AD084  une autorité se reprend par une commande signée
--     AD085  la commande dépensée n'est pas une reprise de CE signataire
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- LA VUE EST EN `security_invoker` : le privilège de la TABLE est exigé aussi.
-- `revoked_at` et `revoked_by` l'ont depuis `tenant_scoped_admins` ; la colonne
-- qui porte la preuve, non.
GRANT UPDATE (revoked_command_id) ON admin.platform_admin TO app_admin_plane;
GRANT UPDATE (revoked_command_id) ON admin.admin_tenant   TO app_admin_plane;

GRANT UPDATE (revoked_at, revoked_by, revoked_command_id)
    ON api.platform_admin TO app_admin_plane;
GRANT UPDATE (revoked_at, revoked_by, revoked_command_id)
    ON api.admin_tenant TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

REVOKE UPDATE (revoked_at, revoked_by, revoked_command_id)
    ON api.admin_tenant FROM app_admin_plane;
REVOKE UPDATE (revoked_at, revoked_by, revoked_command_id)
    ON api.platform_admin FROM app_admin_plane;

REVOKE UPDATE (revoked_command_id) ON admin.admin_tenant   FROM app_admin_plane;
REVOKE UPDATE (revoked_command_id) ON admin.platform_admin FROM app_admin_plane;

RESET ROLE;
