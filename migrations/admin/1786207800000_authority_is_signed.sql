-- Up Migration

-- CRÉER UN ADMINISTRATEUR N'EXIGEAIT AUCUNE PREUVE DE PRÉSENCE.
--
-- `admin.impersonation` porte `command_id NOT NULL` : on ne prend pas la place
-- d'un utilisateur sans qu'une clé matérielle ait été touchée. C'est juste, et
-- c'était la SEULE table dans ce cas.
--
-- `platform_admin` et `admin_tenant` — c'est-à-dire l'acte le plus lourd du
-- produit, celui qui fabrique quelqu'un capable de tout le reste — n'avaient
-- rien. `app_admin_plane` a `INSERT` direct dessus. Conséquence concrète : un
-- jeton porteur d'administration volé permet, pendant sa fenêtre de quinze
-- minutes et SANS TOUCHER LA CLÉ, d'accorder l'autorité de plateforme.
--
-- La règle du produit est pourtant explicite : toute création, modification ou
-- suppression faite en tant qu'administrateur se valide avec la clé, et se
-- signe avec celle de la session. Elle était appliquée à l'usurpation et à
-- rien d'autre.
--
--
-- ═══ LA MÊME FORME QUE L'USURPATION, ET POUR LA MÊME RAISON ═══
--
-- `impersonation_guard` exige que la commande dépensée soit CELLE-CI : même
-- opérateur, même client, action d'usurpation. Trois égalités, sinon une
-- présence prouvée pour « déclarer un SSO » ouvrirait le compte d'un client.
--
-- Ici c'est quatre : l'action (`authority.grant` ou `authority.revoke`), la
-- portée, la cible, et surtout `command.user_id = granted_by`. Cette dernière
-- est celle qui compte — sans elle, un administrateur signerait une commande
-- et un autre s'en servirait pour accorder.
--
--
-- ═══ POURQUOI PAS `NOT NULL` ═══
--
-- Deux raisons, et aucune n'est une commodité.
--
-- La GENÈSE : la première autorité de plateforme est écrite avant qu'aucune
-- session, aucune clé et aucun défi n'existent. Exiger une commande signée
-- rendrait la base impossible à amorcer. La même exemption que AD079, à la
-- même condition — `platform_admin` VIDE, ce qui n'arrive qu'une fois puisque
-- la table refuse la suppression.
--
-- L'HISTOIRE : les octrois déjà écrits n'ont pas de commande, et on ne va pas
-- leur en inventer une. Le déclencheur ne regarde que les lignes NOUVELLES ;
-- les anciennes gardent leur NULL, qui dit la vérité — personne n'a signé,
-- parce qu'à l'époque personne ne le devait.
--
-- `admin_tenant` n'a AUCUNE exemption : le jour où l'on accorde le premier
-- administrateur d'un client, la plateforme a des admins, des sessions et des
-- clés.
--
--
-- ═══ DEUX COLONNES, PAS UNE ═══
--
-- Révoquer est aussi une action, et c'est même la plus discrète : neutraliser
-- les administrateurs d'un client ne ressemble pas à une attaque dans un
-- journal. `revoked_command_id` porte la sienne, avec `authority.revoke`.
--
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD084  an authority is granted, or revoked, by a SIGNED command
--     AD085  the command spent is not this authority's
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

ALTER TABLE admin.platform_admin
    ADD COLUMN command_id         uuid REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT,
    ADD COLUMN revoked_command_id uuid REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT;

ALTER TABLE admin.admin_tenant
    ADD COLUMN command_id         uuid REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT,
    ADD COLUMN revoked_command_id uuid REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT;

COMMENT ON COLUMN admin.platform_admin.command_id IS
'La commande signée qui a produit cet octroi — clé matérielle touchée, empreinte
non rejouable, cible déclarée. NULL sur la ligne de genèse et sur l''historique
antérieur à cette règle : là, personne n''a signé parce que personne ne le
devait, et le NULL dit la vérité.';

COMMENT ON COLUMN admin.platform_admin.revoked_command_id IS
'La commande signée qui a révoqué. Révoquer est une action : neutraliser les
administrateurs d''un client est plus discret que s''accorder des droits.';

COMMENT ON COLUMN admin.admin_tenant.command_id IS
'La commande signée qui a produit cet octroi. Aucune exemption ici, contrairement
à platform_admin : quand on accorde le premier administrateur d''un client, la
plateforme a déjà des admins, des sessions et des clés.';

COMMENT ON COLUMN admin.admin_tenant.revoked_command_id IS
'La commande signée qui a révoqué.';


CREATE FUNCTION admin.authority_is_signed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    -- TG_ARGV[0] : 'PLATFORM' ou 'TENANT'.
    -- TG_ARGV[1] : 'GRANT' ou 'REVOKE'.
    v_scope   text := TG_ARGV[0];
    v_moment  text := TG_ARGV[1];
    v_command uuid;
    v_signer  uuid;
    v_action  text;
    v_tenant  uuid;
BEGIN
    IF v_moment = 'REVOKE' THEN
        IF NEW.revoked_at IS NULL OR OLD.revoked_at IS NOT NULL THEN
            RETURN NEW;
        END IF;
        -- Sans auteur, `revocation_complete` dit mieux la même chose : la
        -- date et l'auteur vont ensemble. On lui laisse la parole.
        IF NEW.revoked_by IS NULL THEN
            RETURN NEW;
        END IF;
        v_command := NEW.revoked_command_id;
        v_signer  := NEW.revoked_by;
        v_action  := 'authority.revoke';
    ELSE
        v_command := NEW.command_id;
        v_signer  := NEW.granted_by;
        v_action  := 'authority.grant';
    END IF;

    IF v_scope = 'TENANT' THEN
        v_tenant := NEW.tenant_id;
    ELSE
        v_tenant := NULL;
    END IF;

    IF v_command IS NULL THEN
        -- LA GENÈSE, et elle seule. Même condition que AD079 : la table vide,
        -- ce qui n'arrive qu'une fois dans la vie de la base.
        IF v_moment = 'GRANT' AND v_scope = 'PLATFORM'
           AND NOT EXISTS (SELECT FROM admin.platform_admin) THEN
            RETURN NEW;
        END IF;

        RAISE EXCEPTION 'an authority is % by a signed command',
            CASE v_moment WHEN 'GRANT' THEN 'granted' ELSE 'revoked' END
            USING ERRCODE = 'AD084',
                  HINT = 'Prove presence, record the command, then write the '
                         'authority — in that order, in one transaction.';
    END IF;

    -- Les quatre égalités. La dernière est celle qui compte : sans elle un
    -- administrateur signe et un autre se sert.
    PERFORM FROM admin.signed_command c
     WHERE c.id = v_command
       AND c.action = v_action
       AND c.scope = v_scope
       AND c.target_tenant_id IS NOT DISTINCT FROM v_tenant
       AND c.user_id = v_signer;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'the command spent is not a % of this authority by %',
            v_action, v_signer
            USING ERRCODE = 'AD085',
                  HINT = 'NEVER RETRY, AND ALERT. Either the command approved '
                         'something else, or it was signed by someone other '
                         'than the person named as granting it.';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.authority_is_signed() FROM PUBLIC;

COMMENT ON FUNCTION admin.authority_is_signed IS
'Ce que `impersonation.command_id` imposait déjà, appliqué à l''acte le plus
lourd du produit. Avant : un jeton porteur volé accordait l''autorité de
plateforme sans qu''aucune clé matérielle ne soit touchée.';


CREATE TRIGGER platform_admin_is_signed
    BEFORE INSERT ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.authority_is_signed('PLATFORM', 'GRANT');

CREATE TRIGGER platform_admin_revocation_is_signed
    BEFORE UPDATE ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.authority_is_signed('PLATFORM', 'REVOKE');

CREATE TRIGGER admin_tenant_is_signed
    BEFORE INSERT ON admin.admin_tenant
    FOR EACH ROW EXECUTE FUNCTION admin.authority_is_signed('TENANT', 'GRANT');

CREATE TRIGGER admin_tenant_revocation_is_signed
    BEFORE UPDATE ON admin.admin_tenant
    FOR EACH ROW EXECUTE FUNCTION admin.authority_is_signed('TENANT', 'REVOKE');


-- `authority_revocation_only` scelle les colonnes de l'octroi. Les deux
-- nouvelles doivent l'être aussi, sinon on repointerait la preuve d'un octroi
-- déjà écrit vers une autre commande.
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

-- Les colonnes rejoignent la liste blanche d'audit : savoir QUELLE commande a
-- produit un octroi est exactement ce qu'on relit après coup.
INSERT INTO audit.auditable_column (schema_name, table_name, column_name)
SELECT 'admin', t, c
  FROM unnest(ARRAY['platform_admin', 'admin_tenant']) AS t,
       unnest(ARRAY['command_id', 'revoked_command_id']) AS c;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin'
   AND table_name IN ('platform_admin', 'admin_tenant')
   AND column_name IN ('command_id', 'revoked_command_id');

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
    IF NEW.user_id    IS DISTINCT FROM OLD.user_id
    OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
    OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
    OR NEW.reason     IS DISTINCT FROM OLD.reason THEN
        RAISE EXCEPTION 'only the revocation may be written, and only once'
            USING ERRCODE = 'AD072';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER admin_tenant_revocation_is_signed ON admin.admin_tenant;
DROP TRIGGER admin_tenant_is_signed ON admin.admin_tenant;
DROP TRIGGER platform_admin_revocation_is_signed ON admin.platform_admin;
DROP TRIGGER platform_admin_is_signed ON admin.platform_admin;

DROP FUNCTION admin.authority_is_signed();

ALTER TABLE admin.admin_tenant
    DROP COLUMN revoked_command_id,
    DROP COLUMN command_id;

ALTER TABLE admin.platform_admin
    DROP COLUMN revoked_command_id,
    DROP COLUMN command_id;

RESET ROLE;
