-- Up Migration

-- Une autorité ne change pas de client.
--
-- ═══ COMMENT CE TROU A ÉTÉ TROUVÉ ═══
--
-- Par le banc de MUTATION, et par lui seul. Il retire une garde, relance la
-- campagne, et attend du rouge. En écrivant le test qui devait tuer le mutant
-- `admin_tenant_revocation_only`, la ligne suivante est passée sans un mot :
--
--     UPDATE admin.admin_tenant SET tenant_id = <un autre client> WHERE id = …
--
-- `authority_revocation_only` scelle `user_id`, `granted_at`, `granted_by`,
-- `command_id` et `reason`. Il ne scellait PAS `tenant_id` — la seule colonne
-- qui dise de quel client il s'agit.
--
-- ═══ CE QUE ÇA PERMETTAIT ═══
--
-- Déplacer une autorité vivante d'un client à un autre par un simple UPDATE.
-- Sans commande signée, sans révocation, sans nouvelle cérémonie — et sans que
-- la ligne cesse d'avoir l'air légitime : sa date d'octroi, son motif et la
-- signature de celui qui l'a accordée restent ceux du client d'origine.
--
-- Quelqu'un habilité sur un client d'essai se retrouvait habilité chez un vrai,
-- et le journal d'audit ne montrait qu'un UPDATE d'une colonne. C'est exactement
-- la forme d'escalade que le reste de ce schéma s'échine à rendre impossible.
--
-- ═══ CE QUE ÇA NE PERMETTAIT PAS ═══
--
-- Le rôle applicatif n'a d'UPDATE que sur `revoked_at` et `revoked_by` — le
-- privilège de colonne l'arrêtait. La porte n'était donc ouverte qu'au
-- propriétaire du schéma : une migration, une console d'administration, ou une
-- injection dans un chemin qui s'y hisserait. C'est plus étroit qu'une faille
-- d'application, et ce n'est pas une raison de la laisser : toute la doctrine de
-- cette base est que l'invariant vit dans le DDL, pas dans la discipline de
-- celui qui écrit la requête.
--
-- `platform_admin` n'est pas concernée : elle n'a pas de client.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. AD072 — « seule la révocation s'écrit » — couvre
--   désormais une colonne de plus, ce qui est précisément ce qu'il disait
--   déjà faire.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE OR REPLACE FUNCTION admin.authority_revocation_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- AD077 EN PREMIER, comme avant : le terme est fixé à l'octroi, et le
    -- repousser après coup rallongerait une autorité sans qu'aucune décision
    -- ne soit prise.
    IF NEW.expires_at IS DISTINCT FROM OLD.expires_at
    OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
    OR NEW.break_glass IS DISTINCT FROM OLD.break_glass THEN
        RAISE EXCEPTION 'the term of a grant is settled: revoke and re-grant'
            USING ERRCODE = 'AD077';
    END IF;

    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'this authority is already revoked'
            USING ERRCODE = 'AD072';
    END IF;

    -- `to_jsonb(OLD) ? 'tenant_id'` PLUTÔT QU'UNE SECONDE FONCTION.
    --
    -- Ce déclencheur sert les deux portées, et `platform_admin` n'a pas de
    -- colonne `tenant_id` : la nommer directement ferait échouer la compilation
    -- du corps à l'exécution sur cette table. Le test d'existence coûte une
    -- conversion par ligne modifiée — et une autorité se révoque quelques fois
    -- par an, jamais en boucle.
    IF NEW.user_id    IS DISTINCT FROM OLD.user_id
    OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
    OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
    OR NEW.command_id IS DISTINCT FROM OLD.command_id
    OR NEW.reason     IS DISTINCT FROM OLD.reason
    OR (to_jsonb(OLD) ? 'tenant_id'
        AND to_jsonb(NEW) -> 'tenant_id' IS DISTINCT FROM to_jsonb(OLD) -> 'tenant_id') THEN
        RAISE EXCEPTION 'only the revocation may be written, and only once'
            USING ERRCODE = 'AD072';
    END IF;

    RETURN NEW;
END;
$$;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

CREATE OR REPLACE FUNCTION admin.authority_revocation_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.expires_at IS DISTINCT FROM OLD.expires_at
    OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
    OR NEW.break_glass IS DISTINCT FROM OLD.break_glass THEN
        RAISE EXCEPTION 'the term of a grant is settled: revoke and re-grant'
            USING ERRCODE = 'AD077';
    END IF;

    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'this authority is already revoked'
            USING ERRCODE = 'AD072';
    END IF;
    IF NEW.user_id    IS DISTINCT FROM OLD.user_id
    OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
    OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
    OR NEW.command_id IS DISTINCT FROM OLD.command_id
    OR NEW.reason     IS DISTINCT FROM OLD.reason THEN
        RAISE EXCEPTION 'only the revocation may be written, and only once'
            USING ERRCODE = 'AD072';
    END IF;

    RETURN NEW;
END;
$$;

RESET ROLE;
