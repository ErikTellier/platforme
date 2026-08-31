-- Up Migration

-- L'AUTORITÉ D'ADMINISTRATION NE S'ARRÊTAIT JAMAIS TOUTE SEULE.
--
-- Après lecture des pratiques de gestion des accès à privilèges et du NIST
-- SP 800-53 (familles AC-2, AC-5, AC-6), trois manques.
--
--
-- ═══ 1. UN DROIT PERMANENT EST UN DROIT QU'ON OUBLIE ═══
--
-- `platform_admin` et `admin_tenant` accordaient jusqu'à révocation. C'est
-- un droit permanent, et un droit permanent ne se retire que si quelqu'un y
-- pense — ce que personne ne fait, parce que rien ne le rappelle.
--
-- Le modèle « juste à temps » dit l'inverse : on accorde POUR UNE DURÉE, et
-- le droit tombe seul. La différence n'est pas cosmétique. Un compte
-- d'administration compromis six mois après la fin de la mission de son
-- titulaire donne la plateforme entière ; le même compte avec une autorité
-- de huit heures ne donne rien du tout.
--
-- Et c'est une expiration DÉRIVÉE, comme partout ici : `expires_at` est un
-- fait posé à l'octroi, l'autorité vivante se calcule. Pas de tâche
-- planifiée qui révoque, donc pas de tâche planifiée qui tombe en panne un
-- dimanche sans que personne le voie.
--
--
-- ═══ 2. UN SEUL HOMME POUVAIT FABRIQUER UN ADMINISTRATEUR DE PLATEFORME ═══
--
-- `granted_by` était une seule personne, et rien n'interdisait de s'octroyer
-- l'autorité à soi-même. Le plus haut privilège du produit se créait donc
-- par une signature unique — c'est le contrôle de séparation des tâches qui
-- manque (NIST AC-5).
--
-- Le second approbateur est exigé pour la PLATEFORME seulement. C'est
-- proportionné : une autorité de tenant est bornée à un client, une autorité
-- de plateforme les tient tous. Imposer deux personnes partout ferait
-- surtout inventer des contournements.
--
--
-- ═══ 3. ET SI LES DEUX APPROBATEURS SONT INJOIGNABLES ? ═══
--
-- Une règle des quatre yeux sans issue de secours produit un blocage le jour
-- où il ne faut pas : incident de nuit, deux personnes en avion. Les gens
-- contournent alors la règle par un moyen non prévu, donc non tracé.
--
-- Le bris de glace est ce contournement, mais PRÉVU : une seule signature,
-- un motif obligatoire, la même durée maximale, et une ligne qui se voit.
-- On ne l'empêche pas, on le rend impossible à faire discrètement.
--
--
-- LA POLITIQUE EST UNE TABLE, PAS UN CHIFFRE DANS UNE FONCTION. Une
-- organisation plus stricte que ce défaut resserre une durée sans migration,
-- et le chiffre reste lisible par quelqu'un qui n'ouvre pas le code.
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD073  the grant outlives the maximum duration of its scope
--     AD074  authority is never granted to oneself
--     AD075  this scope requires a second, distinct approver
--     AD076  break-glass is not open to this scope
--     AD077  the term of a grant is settled: revoke and re-grant
--     AD078  no policy is declared for this authority scope (fails closed)
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- =====================================================================
--  1. LA POLITIQUE
-- =====================================================================

CREATE TABLE admin.authority_scope (
    scope                     text        NOT NULL,
    description               text        NOT NULL,
    -- Au-delà, l'octroi est refusé. Pas tronqué silencieusement : quelqu'un
    -- qui demande six mois doit apprendre que six mois n'existent pas, pas
    -- croire qu'il les a eus.
    max_duration              interval    NOT NULL,
    requires_second_approver  boolean     NOT NULL,
    allows_break_glass        boolean     NOT NULL,

    CONSTRAINT authority_scope_pk PRIMARY KEY (scope),
    CONSTRAINT authority_scope_duration_positive CHECK (
        max_duration > interval '0'),
    -- Un bris de glace n'a de sens que là où il y a une règle à briser.
    -- L'ouvrir sur un périmètre sans second approbateur créerait un drapeau
    -- « urgence » sans contrainte contournée, c'est-à-dire un mensonge.
    CONSTRAINT authority_scope_break_glass_needs_a_rule CHECK (
        NOT allows_break_glass OR requires_second_approver)
);

INSERT INTO admin.authority_scope
       (scope, description, max_duration, requires_second_approver, allows_break_glass)
VALUES
  ('PLATFORM',
   'Toute la plateforme, tous les tenants. Le plus haut privilège du produit.',
   interval '8 hours', TRUE, TRUE),
  ('TENANT',
   'Un seul client. Bornée par construction, donc régie plus souplement.',
   interval '90 days', FALSE, FALSE);

COMMENT ON TABLE admin.authority_scope IS
'Ce qu''un périmètre d''autorité autorise : combien de temps au plus, et à
combien de signatures. La politique est ici et non dans une fonction, pour
qu''une organisation la resserre sans migration et qu''un auditeur la lise
sans ouvrir le code.';


-- =====================================================================
--  2. LES DEUX TABLES D'AUTORITÉ
-- =====================================================================

ALTER TABLE admin.platform_admin
    -- Le défaut est la durée la PLUS COURTE admise par le périmètre : un
    -- oubli produit huit heures d'autorité, pas six mois. Une omission doit
    -- refuser, jamais accorder.
    ADD COLUMN expires_at  timestamptz NOT NULL DEFAULT now() + interval '8 hours',
    ADD COLUMN approved_by uuid,
    ADD COLUMN break_glass boolean     NOT NULL DEFAULT FALSE;

ALTER TABLE admin.platform_admin
    ADD CONSTRAINT platform_admin_approved_by_fk
        FOREIGN KEY (approved_by) REFERENCES admin."user" (id),
    ADD CONSTRAINT platform_admin_expires_after_granted CHECK (
        expires_at > granted_at);

ALTER TABLE admin.admin_tenant
    ADD COLUMN expires_at  timestamptz NOT NULL DEFAULT now() + interval '90 days',
    ADD COLUMN approved_by uuid,
    ADD COLUMN break_glass boolean     NOT NULL DEFAULT FALSE;

ALTER TABLE admin.admin_tenant
    ADD CONSTRAINT admin_tenant_approved_by_fk
        FOREIGN KEY (approved_by) REFERENCES admin."user" (id),
    ADD CONSTRAINT admin_tenant_expires_after_granted CHECK (
        expires_at > granted_at);

CREATE INDEX ix_platform_admin_live ON admin.platform_admin (user_id, expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX ix_admin_tenant_live ON admin.admin_tenant (user_id, tenant_id, expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX ix_platform_admin_break_glass ON admin.platform_admin (granted_at)
    WHERE break_glass;

COMMENT ON COLUMN admin.platform_admin.expires_at IS
'L''autorité tombe seule à cette date. Aucune tâche planifiée ne la
révoque : l''expiration est DÉRIVÉE à la lecture, donc elle ne peut pas
tomber en panne un dimanche sans que personne le voie.';

COMMENT ON COLUMN admin.platform_admin.break_glass IS
'Octroi d''urgence à une seule signature. On ne l''empêche pas — une règle
des quatre yeux sans issue de secours se contourne par un moyen non tracé —
on le rend impossible à faire discrètement.';


-- =====================================================================
--  3. LA GARDE
-- =====================================================================

CREATE OR REPLACE FUNCTION admin.authority_grant_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    pol admin.authority_scope%ROWTYPE;
BEGIN
    IF EXISTS (SELECT FROM admin."user" u
                WHERE u.id = NEW.user_id AND u.deactivated_at IS NOT NULL) THEN
        RAISE EXCEPTION 'admin % is deactivated: authority would lie dormant',
            NEW.user_id
            USING ERRCODE = 'AD070';
    END IF;

    SELECT * INTO pol FROM admin.authority_scope WHERE scope = TG_ARGV[0];

    -- FERMÉ PAR DÉFAUT. Sans cette ligne, supprimer la politique désarmait
    -- tout le contrôle : pol.max_duration valait NULL, la comparaison valait
    -- NULL, aucun refus ne se déclenchait — dix ans d'autorité plateforme
    -- sans approbateur passaient. Une garde qui perd sa règle doit refuser,
    -- pas se taire. (La table refuse aussi la suppression, mais deux
    -- protections valent mieux qu'une quand l'enjeu est celui-là.)
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no policy is declared for the % authority scope',
            TG_ARGV[0]
            USING ERRCODE = 'AD078';
    END IF;

    IF NEW.expires_at - NEW.granted_at > pol.max_duration THEN
        RAISE EXCEPTION
            'a % grant may not run longer than %, asked for %',
            pol.scope, pol.max_duration, NEW.expires_at - NEW.granted_at
            USING ERRCODE = 'AD073',
                  HINT = 'Grant again when it lapses; that is the point.';
    END IF;

    -- S'octroyer l'autorité à soi-même supprime le contrôle quel que soit le
    -- reste : celui qui signe est celui qui reçoit.
    IF NEW.granted_by = NEW.user_id THEN
        RAISE EXCEPTION 'authority is never granted to oneself'
            USING ERRCODE = 'AD074';
    END IF;

    IF NEW.break_glass THEN
        IF NOT pol.allows_break_glass THEN
            RAISE EXCEPTION 'break-glass is not open to the % scope', pol.scope
                USING ERRCODE = 'AD076';
        END IF;
        -- Une seule signature, assumée. Le drapeau et le motif sont la
        -- contrepartie, et la vue break_glass les expose.
        RETURN NEW;
    END IF;

    IF pol.requires_second_approver THEN
        IF NEW.approved_by IS NULL
           OR NEW.approved_by = NEW.granted_by
           OR NEW.approved_by = NEW.user_id THEN
            RAISE EXCEPTION
                '% authority requires a second approver, distinct from both '
                'the grantor and the grantee', pol.scope
                USING ERRCODE = 'AD075',
                      HINT = 'Or post it as break_glass, which is recorded as such.';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER platform_admin_grant_guard ON admin.platform_admin;
CREATE TRIGGER platform_admin_grant_guard
    BEFORE INSERT ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.authority_grant_guard('PLATFORM');

DROP TRIGGER admin_tenant_grant_guard ON admin.admin_tenant;
CREATE TRIGGER admin_tenant_grant_guard
    BEFORE INSERT ON admin.admin_tenant
    FOR EACH ROW EXECUTE FUNCTION admin.authority_grant_guard('TENANT');


-- Le terme est fixé à l'octroi. Le repousser après coup rallongerait une
-- autorité sans nouvelle décision — c'est-à-dire exactement le droit
-- permanent qu'on vient de supprimer, reconstitué par la petite porte.
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
    OR NEW.reason     IS DISTINCT FROM OLD.reason THEN
        RAISE EXCEPTION 'only the revocation may be written, and only once'
            USING ERRCODE = 'AD072';
    END IF;

    RETURN NEW;
END;
$$;


-- =====================================================================
--  4. CE QUE L'AUTORITÉ VIVANTE DEVIENT
-- =====================================================================

CREATE OR REPLACE FUNCTION admin.may_operate(p_user uuid, p_tenant uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT EXISTS (
    SELECT FROM admin.platform_admin p
     WHERE p.user_id = p_user AND p.revoked_at IS NULL
       AND now() < p.expires_at)
  OR EXISTS (
    SELECT FROM admin.admin_tenant t
     WHERE t.user_id = p_user AND t.tenant_id = p_tenant
       AND t.revoked_at IS NULL
       AND now() < t.expires_at);
$$;

-- DROP puis CREATE : la vue gagne quatre colonnes au milieu, et
-- CREATE OR REPLACE ne sait ni renommer ni réordonner.
DROP VIEW admin.effective_authority;

CREATE VIEW admin.effective_authority
    WITH (security_invoker = TRUE)
AS
 SELECT u.id AS user_id, 'PLATFORM'::text AS scope, NULL::uuid AS tenant_id,
        p.granted_at, p.granted_by, p.approved_by, p.break_glass, p.reason,
        p.expires_at, p.expires_at - now() AS time_left
   FROM admin.platform_admin AS p
   INNER JOIN admin."user" AS u ON p.user_id = u.id
  WHERE p.revoked_at IS NULL AND u.deactivated_at IS NULL
    AND now() < p.expires_at
UNION ALL
 SELECT u.id, 'TENANT'::text, t.tenant_id,
        t.granted_at, t.granted_by, t.approved_by, t.break_glass, t.reason,
        t.expires_at, t.expires_at - now()
   FROM admin.admin_tenant AS t
   INNER JOIN admin."user" AS u ON t.user_id = u.id
  WHERE t.revoked_at IS NULL AND u.deactivated_at IS NULL
    AND now() < t.expires_at;

COMMENT ON VIEW admin.effective_authority IS
'L''autorité qui vaut MAINTENANT : ni révoquée, ni expirée, sur un compte
vivant. Une autorité expirée n''est pas effacée — la ligne reste, et
l''historique dit qui pouvait quoi le jour où c''est arrivé.';


CREATE VIEW admin.break_glass_use
    WITH (security_invoker = TRUE)
AS
 SELECT 'PLATFORM'::text AS scope, NULL::uuid AS tenant_id,
        p.user_id, p.granted_by, p.granted_at, p.expires_at, p.reason,
        (p.revoked_at IS NULL AND now() < p.expires_at) AS still_live
   FROM admin.platform_admin AS p WHERE p.break_glass
UNION ALL
 SELECT 'TENANT'::text, t.tenant_id,
        t.user_id, t.granted_by, t.granted_at, t.expires_at, t.reason,
        (t.revoked_at IS NULL AND now() < t.expires_at)
   FROM admin.admin_tenant AS t WHERE t.break_glass;

COMMENT ON VIEW admin.break_glass_use IS
'Tout octroi passé par l''issue de secours, vivant ou non. C''est la liste
qu''on relit après coup — un bris de glace n''est pas une faute, mais un
bris de glace qui ne se relit pas en est une.';


-- La politique porte de la preuve autant que les octrois qu'elle régit :
-- supprimer une ligne rendrait illisible la règle qui s'appliquait le jour
-- d'un octroi passé.
CREATE TRIGGER authority_scope_no_delete
    BEFORE DELETE ON admin.authority_scope
    FOR EACH ROW EXECUTE FUNCTION admin.authority_no_delete();

GRANT SELECT ON admin.authority_scope   TO admin_app;
GRANT SELECT ON admin.break_glass_use   TO admin_app;

REVOKE EXECUTE ON FUNCTION admin.authority_revocation_only() FROM PUBLIC;

RESET ROLE;

SELECT audit.watch('admin', 'platform_admin',
       '{id, user_id, granted_at, granted_by, approved_by, break_glass, reason,
         expires_at, revoked_at, revoked_by}');
SELECT audit.watch('admin', 'admin_tenant',
       '{id, user_id, tenant_id, granted_at, granted_by, approved_by,
         break_glass, reason, expires_at, revoked_at, revoked_by}');
SELECT audit.watch('admin', 'authority_scope',
       '{scope, max_duration, requires_second_approver, allows_break_glass}');

-- Down Migration

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name = 'authority_scope';
DELETE FROM audit.watched
 WHERE schema_name = 'admin' AND table_name = 'authority_scope';
SELECT audit.watch('admin', 'platform_admin',
       '{id, user_id, granted_at, granted_by, reason, revoked_at, revoked_by}');
SELECT audit.watch('admin', 'admin_tenant',
       '{id, user_id, tenant_id, granted_at, granted_by, reason, revoked_at,
         revoked_by}');

DROP VIEW admin.break_glass_use;

DROP VIEW admin.effective_authority;

CREATE VIEW admin.effective_authority
    WITH (security_invoker = TRUE)
AS
 SELECT u.id AS user_id, 'PLATFORM'::text AS scope, NULL::uuid AS tenant_id,
        p.granted_at, p.granted_by, p.reason
   FROM admin.platform_admin AS p
   INNER JOIN admin."user" AS u ON p.user_id = u.id
  WHERE p.revoked_at IS NULL AND u.deactivated_at IS NULL
UNION ALL
 SELECT u.id, 'TENANT'::text, t.tenant_id, t.granted_at, t.granted_by, t.reason
   FROM admin.admin_tenant AS t
   INNER JOIN admin."user" AS u ON t.user_id = u.id
  WHERE t.revoked_at IS NULL AND u.deactivated_at IS NULL;

CREATE OR REPLACE FUNCTION admin.may_operate(p_user uuid, p_tenant uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT EXISTS (
    SELECT FROM admin.platform_admin p
     WHERE p.user_id = p_user AND p.revoked_at IS NULL)
  OR EXISTS (
    SELECT FROM admin.admin_tenant t
     WHERE t.user_id = p_user AND t.tenant_id = p_tenant
       AND t.revoked_at IS NULL);
$$;

CREATE OR REPLACE FUNCTION admin.authority_revocation_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
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

DROP TRIGGER admin_tenant_grant_guard ON admin.admin_tenant;
DROP TRIGGER platform_admin_grant_guard ON admin.platform_admin;

CREATE OR REPLACE FUNCTION admin.authority_grant_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    IF EXISTS (SELECT FROM admin."user" u
                WHERE u.id = NEW.user_id AND u.deactivated_at IS NOT NULL) THEN
        RAISE EXCEPTION 'admin % is deactivated: authority would lie dormant',
            NEW.user_id
            USING ERRCODE = 'AD070';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_admin_grant_guard
    BEFORE INSERT ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.authority_grant_guard();
CREATE TRIGGER admin_tenant_grant_guard
    BEFORE INSERT ON admin.admin_tenant
    FOR EACH ROW EXECUTE FUNCTION admin.authority_grant_guard();

ALTER TABLE admin.admin_tenant
    DROP CONSTRAINT admin_tenant_expires_after_granted,
    DROP CONSTRAINT admin_tenant_approved_by_fk,
    DROP COLUMN break_glass,
    DROP COLUMN approved_by,
    DROP COLUMN expires_at;

ALTER TABLE admin.platform_admin
    DROP CONSTRAINT platform_admin_expires_after_granted,
    DROP CONSTRAINT platform_admin_approved_by_fk,
    DROP COLUMN break_glass,
    DROP COLUMN approved_by,
    DROP COLUMN expires_at;

DROP TRIGGER authority_scope_no_delete ON admin.authority_scope;
DROP TABLE admin.authority_scope;
