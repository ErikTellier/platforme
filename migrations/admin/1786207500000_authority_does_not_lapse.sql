-- Up Migration

-- ÊTRE ADMINISTRATEUR N'EST PAS UNE CHOSE QUI EXPIRE.
--
-- `jit_authority` a posé un terme OBLIGATOIRE sur toute autorité : huit heures
-- pour la plateforme, quatre-vingt-dix jours pour un client, par défaut de
-- colonne. Le raisonnement — le juste-à-temps, l'autorité qu'on ne détient pas
-- en permanence — est celui des produits d'élévation temporaire, et il ne
-- décrit pas ce produit.
--
-- Il confondait deux faits dans une seule table :
--
--   « Untel fait partie des administrateurs »   — une décision rare, révocable
--   « l'autorité d'Untel est active à l'instant » — ce qui, là, serait court
--
-- Avec une seule table, le plafond s'applique aux deux. Ré-accorder revient
-- donc à RE-DÉCIDER QUI EST ADMINISTRATEUR, trois fois par jour pour la
-- plateforme et quatre fois par an pour chaque client. Le second est le pire :
-- quatre-vingt-dix jours après chaque raccordement, l'éditeur reçoit un
-- ticket par client disant « nous avons perdu nos droits ». Une conception
-- qui produit mécaniquement un incident par client et par trimestre est
-- fausse, quelle que soit sa cohérence interne.
--
-- L'autorité s'éteint donc par RÉVOCATION, et par rien d'autre. C'est un fait
-- que quelqu'un pose, daté et signé — comme tout le reste de cette base.
--
--
-- ═══ FACULTATIF, PAS SUPPRIMÉ ═══
--
-- Le terme reste possible et cesse d'être imposé. Un prestataire pendant une
-- fenêtre de migration est un vrai cas, et le semis le nommait déjà dans ses
-- motifs. Ce qui disparaît, c'est le DÉFAUT DE COLONNE : une autorité
-- accordée sans qu'on parle de durée n'en a pas.
--
-- Et rien n'est réécrit. Une ligne qui porte une échéance la garde, avec le
-- sens qu'elle avait le jour où elle a été posée. L'alternative — changer le
-- sens de la colonne sous les lignes existantes — ferait RESSUSCITER toutes
-- les autorités expirées de l'historique au moment du déploiement. C'est
-- exactement la classe de bug que cette base refuse partout ailleurs : le
-- passé ne se relit pas à la lumière d'une règle postérieure.
--
--
-- ═══ CE QUI REMPLACE LE TERME ═══
--
-- Rien, parce que le terme ne protégeait pas grand-chose : une autorité de
-- huit heures détenue par quelqu'un qui la ré-obtient trois fois par jour est
-- une autorité permanente avec de la paperasse.
--
-- Ce qui protège vraiment était déjà là, et ne dépend pas d'une horloge :
--
--   · une session d'une heure, plafond non extensible ;
--   · une clé matérielle à CHAQUE action lourde, pas une fois par jour ;
--   · une commande signée, enregistrée avant l'exécution, non rejouable ;
--   · une portée : hors d'elle, l'autorité est nulle ;
--   · et depuis la migration précédente, un signataire qui doit lui-même
--     détenir l'autorité qu'il accorde.
--
-- Cette dernière gagne au change. Elle portait un risque de verrouillage —
-- si toutes les autorités expiraient la même nuit, plus personne ne pouvait
-- en accorder. Sans expiration, le cas n'existe plus.
--
--
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. AD073 (durée au-delà du plafond) et AD077 (le terme
--   est scellé) restent en vigueur POUR LES OCTROIS QUI PORTENT UN TERME —
--   ils deviennent conditionnels, pas morts.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- =====================================================================
--  1. LA POLITIQUE N'IMPOSE PLUS DE PLAFOND
-- =====================================================================

ALTER TABLE admin.authority_scope
    ALTER COLUMN max_duration DROP NOT NULL;

ALTER TABLE admin.authority_scope
    DROP CONSTRAINT authority_scope_duration_positive,
    ADD  CONSTRAINT authority_scope_duration_positive CHECK (
        max_duration IS NULL OR max_duration > interval '0');

-- `max_impersonation` reste NOT NULL : la durée d'une USURPATION est bornée,
-- elle, et c'est une autre question. Sans plafond d'autorité, il n'y a plus
-- rien au-dessus d'elle à respecter.
ALTER TABLE admin.authority_scope
    DROP CONSTRAINT authority_scope_impersonation_within_authority,
    ADD  CONSTRAINT authority_scope_impersonation_within_authority CHECK (
        max_duration IS NULL OR max_impersonation <= max_duration);

UPDATE admin.authority_scope SET max_duration = NULL;

COMMENT ON COLUMN admin.authority_scope.max_duration IS
'Plafond de durée SI un octroi porte un terme. NULL = aucun plafond, et c''est
le cas des deux périmètres : être administrateur n''expire pas. Une
organisation qui veut des autorités temporaires repose un intervalle ici, sans
migration — AD073 se remet à refuser tout seul.';


-- =====================================================================
--  2. LE TERME DEVIENT FACULTATIF
-- =====================================================================

-- LE DÉFAUT DE COLONNE EST CE QUI FABRIQUAIT LES TERMES. Personne ne
-- demandait huit heures : la colonne les ajoutait en silence.
ALTER TABLE admin.platform_admin
    ALTER COLUMN expires_at DROP DEFAULT,
    ALTER COLUMN expires_at DROP NOT NULL;

ALTER TABLE admin.admin_tenant
    ALTER COLUMN expires_at DROP DEFAULT,
    ALTER COLUMN expires_at DROP NOT NULL;

ALTER TABLE admin.platform_admin
    DROP CONSTRAINT platform_admin_expires_after_granted,
    ADD  CONSTRAINT platform_admin_expires_after_granted CHECK (
        expires_at IS NULL OR expires_at > granted_at);

ALTER TABLE admin.admin_tenant
    DROP CONSTRAINT admin_tenant_expires_after_granted,
    ADD  CONSTRAINT admin_tenant_expires_after_granted CHECK (
        expires_at IS NULL OR expires_at > granted_at);

COMMENT ON COLUMN admin.platform_admin.expires_at IS
'Terme FACULTATIF. NULL = l''autorité ne s''éteint que par révocation, et c''est
le cas normal : on ne re-décide pas trois fois par jour qui administre la
plateforme. Une date reste possible pour une intervention bornée.';

COMMENT ON COLUMN admin.admin_tenant.expires_at IS
'Terme FACULTATIF. NULL = l''autorité ne s''éteint que par révocation. Le
défaut précédent — quatre-vingt-dix jours — produisait un ticket par client et
par trimestre : « nous avons perdu nos droits d''administration ».';


-- =====================================================================
--  3. « VIVANT » VEUT DIRE NON RÉVOQUÉ, ET NON EXPIRÉ S'IL Y A UN TERME
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
       AND (p.expires_at IS NULL OR now() < p.expires_at))
  OR EXISTS (
    SELECT FROM admin.admin_tenant t
     WHERE t.user_id = p_user AND t.tenant_id = p_tenant
       AND t.revoked_at IS NULL
       AND (t.expires_at IS NULL OR now() < t.expires_at));
$$;

-- `WITH` EST OBLIGATOIRE ICI, MEME EN REMPLACEMENT.
--
-- `CREATE OR REPLACE VIEW` REINITIALISE les options de la vue : l'omettre ne
-- « garde pas l'existant », il l'efface. La vue retombe alors en
-- `security_definer` implicite et s'execute avec les droits de son
-- proprietaire, `admin_owner` — a qui la politique `owner_is_the_vetted_path`
-- rend `true` sans condition. Le plan devient un `Seq Scan` SANS filtre, et
-- toutes les lignes de tous les clients remontent.
--
-- Constate en base, plan a l'appui : l'option avait disparu de trois vues.
CREATE OR REPLACE VIEW admin.effective_authority
    WITH (security_invoker = TRUE)
AS
 SELECT u.id AS user_id, 'PLATFORM'::text AS scope, NULL::uuid AS tenant_id,
        p.granted_at, p.granted_by, p.approved_by, p.break_glass, p.reason,
        p.expires_at, p.expires_at - now() AS time_left
   FROM admin.platform_admin AS p
   INNER JOIN admin."user" AS u ON p.user_id = u.id
  WHERE p.revoked_at IS NULL AND u.deactivated_at IS NULL
    AND (p.expires_at IS NULL OR now() < p.expires_at)
UNION ALL
 SELECT u.id, 'TENANT'::text, t.tenant_id,
        t.granted_at, t.granted_by, t.approved_by, t.break_glass, t.reason,
        t.expires_at, t.expires_at - now()
   FROM admin.admin_tenant AS t
   INNER JOIN admin."user" AS u ON t.user_id = u.id
  WHERE t.revoked_at IS NULL AND u.deactivated_at IS NULL
    AND (t.expires_at IS NULL OR now() < t.expires_at);

COMMENT ON VIEW admin.effective_authority IS
'Qui peut opérer sur quoi, MAINTENANT. `time_left` vaut NULL quand l''autorité
ne porte pas de terme — c''est-à-dire dans le cas normal. Une interface qui
affichait un décompte doit lire NULL comme « jusqu''à révocation », jamais
comme « expiré ».';

-- `WITH` EST OBLIGATOIRE ICI, MEME EN REMPLACEMENT.
--
-- `CREATE OR REPLACE VIEW` REINITIALISE les options de la vue : l'omettre ne
-- « garde pas l'existant », il l'efface. La vue retombe alors en
-- `security_definer` implicite et s'execute avec les droits de son
-- proprietaire, `admin_owner` — a qui la politique `owner_is_the_vetted_path`
-- rend `true` sans condition. Le plan devient un `Seq Scan` SANS filtre, et
-- toutes les lignes de tous les clients remontent.
--
-- Constate en base, plan a l'appui : l'option avait disparu de trois vues.
CREATE OR REPLACE VIEW admin.break_glass_use
    WITH (security_invoker = TRUE)
AS
 SELECT 'PLATFORM'::text AS scope, NULL::uuid AS tenant_id,
        p.user_id, p.granted_by, p.granted_at, p.expires_at, p.reason,
        (p.revoked_at IS NULL
         AND (p.expires_at IS NULL OR now() < p.expires_at)) AS still_live
   FROM admin.platform_admin AS p WHERE p.break_glass
UNION ALL
 SELECT 'TENANT'::text, t.tenant_id,
        t.user_id, t.granted_by, t.granted_at, t.expires_at, t.reason,
        (t.revoked_at IS NULL
         AND (t.expires_at IS NULL OR now() < t.expires_at))
   FROM admin.admin_tenant AS t WHERE t.break_glass;


-- =====================================================================
--  4. LE PLAFOND NE SE VÉRIFIE QUE S'IL Y EN A UN
-- =====================================================================

CREATE OR REPLACE FUNCTION admin.authority_grant_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    pol record;
BEGIN
    IF EXISTS (SELECT FROM admin."user" u
                WHERE u.id = NEW.user_id AND u.deactivated_at IS NOT NULL) THEN
        RAISE EXCEPTION 'admin % is deactivated: authority would lie dormant',
            NEW.user_id
            USING ERRCODE = 'AD070';
    END IF;

    SELECT * INTO pol FROM admin.authority_scope WHERE scope = TG_ARGV[0];

    -- FERMÉ PAR DÉFAUT, et ça n'a pas changé : une politique absente n'est pas
    -- une politique permissive. Ce qui a changé, c'est qu'une politique
    -- PRÉSENTE peut désormais ne déclarer aucun plafond.
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no policy is declared for the % authority scope',
            TG_ARGV[0]
            USING ERRCODE = 'AD078';
    END IF;

    -- Deux conditions, et les deux comptent : pas de terme, rien à plafonner ;
    -- pas de plafond, rien à faire respecter.
    IF NEW.expires_at IS NOT NULL AND pol.max_duration IS NOT NULL
       AND NEW.expires_at - NEW.granted_at > pol.max_duration THEN
        RAISE EXCEPTION
            'the % scope caps authority at %, asked for %',
            pol.scope, pol.max_duration, NEW.expires_at - NEW.granted_at
            USING ERRCODE = 'AD073',
                  HINT = 'Grant again when it lapses — that is the point of a term.';
    END IF;

    IF NEW.granted_by = NEW.user_id THEN
        RAISE EXCEPTION 'authority is never granted to oneself'
            USING ERRCODE = 'AD074';
    END IF;

    IF NEW.break_glass THEN
        IF NOT pol.allows_break_glass THEN
            RAISE EXCEPTION 'break-glass is not open to the % scope', pol.scope
                USING ERRCODE = 'AD076';
        END IF;
        RETURN NEW;
    END IF;

    IF pol.requires_second_approver THEN
        IF NEW.approved_by IS NULL
        OR NEW.approved_by = NEW.granted_by
        OR NEW.approved_by = NEW.user_id THEN
            RAISE EXCEPTION
                'the % scope requires a second, distinct approver', pol.scope
                USING ERRCODE = 'AD075';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

CREATE OR REPLACE FUNCTION admin.authority_grant_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    pol record;
BEGIN
    IF EXISTS (SELECT FROM admin."user" u
                WHERE u.id = NEW.user_id AND u.deactivated_at IS NOT NULL) THEN
        RAISE EXCEPTION 'admin % is deactivated: authority would lie dormant',
            NEW.user_id
            USING ERRCODE = 'AD070';
    END IF;

    SELECT * INTO pol FROM admin.authority_scope WHERE scope = TG_ARGV[0];

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no policy is declared for the % authority scope',
            TG_ARGV[0]
            USING ERRCODE = 'AD078';
    END IF;

    IF NEW.expires_at - NEW.granted_at > pol.max_duration THEN
        RAISE EXCEPTION
            'the % scope caps authority at %, asked for %',
            pol.scope, pol.max_duration, NEW.expires_at - NEW.granted_at
            USING ERRCODE = 'AD073',
                  HINT = 'Grant again when it lapses — that is the point of a term.';
    END IF;

    IF NEW.granted_by = NEW.user_id THEN
        RAISE EXCEPTION 'authority is never granted to oneself'
            USING ERRCODE = 'AD074';
    END IF;

    IF NEW.break_glass THEN
        IF NOT pol.allows_break_glass THEN
            RAISE EXCEPTION 'break-glass is not open to the % scope', pol.scope
                USING ERRCODE = 'AD076';
        END IF;
        RETURN NEW;
    END IF;

    IF pol.requires_second_approver THEN
        IF NEW.approved_by IS NULL
        OR NEW.approved_by = NEW.granted_by
        OR NEW.approved_by = NEW.user_id THEN
            RAISE EXCEPTION
                'the % scope requires a second, distinct approver', pol.scope
                USING ERRCODE = 'AD075';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

-- `WITH` EST OBLIGATOIRE ICI, MEME EN REMPLACEMENT.
--
-- `CREATE OR REPLACE VIEW` REINITIALISE les options de la vue : l'omettre ne
-- « garde pas l'existant », il l'efface. La vue retombe alors en
-- `security_definer` implicite et s'execute avec les droits de son
-- proprietaire, `admin_owner` — a qui la politique `owner_is_the_vetted_path`
-- rend `true` sans condition. Le plan devient un `Seq Scan` SANS filtre, et
-- toutes les lignes de tous les clients remontent.
--
-- Constate en base, plan a l'appui : l'option avait disparu de trois vues.
CREATE OR REPLACE VIEW admin.break_glass_use
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

-- `WITH` EST OBLIGATOIRE ICI, MEME EN REMPLACEMENT.
--
-- `CREATE OR REPLACE VIEW` REINITIALISE les options de la vue : l'omettre ne
-- « garde pas l'existant », il l'efface. La vue retombe alors en
-- `security_definer` implicite et s'execute avec les droits de son
-- proprietaire, `admin_owner` — a qui la politique `owner_is_the_vetted_path`
-- rend `true` sans condition. Le plan devient un `Seq Scan` SANS filtre, et
-- toutes les lignes de tous les clients remontent.
--
-- Constate en base, plan a l'appui : l'option avait disparu de trois vues.
CREATE OR REPLACE VIEW admin.effective_authority
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

COMMENT ON VIEW admin.effective_authority IS NULL;

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

-- Les lignes sans terme n'ont pas de place dans l'ancien modèle : on leur en
-- redonne un, celui que la colonne aurait mis.
--
-- DÉCLENCHEURS DÉSACTIVÉS LE TEMPS DE L'ÉCRITURE. `authority_revocation_only`
-- porte AD077 — « le terme d'un octroi est scellé » — et il a raison : c'est
-- exactement ce qu'on fait ici. Une descente qui repose un modèle antérieur
-- n'est pas un appelant qui triche, et laisser la garde parler rendait cette
-- migration irréversible dès qu'une seule ligne existait. Trouvé par
-- `roundtrip` sur une base peuplée, pas sur une base vide.
ALTER TABLE admin.platform_admin DISABLE TRIGGER platform_admin_revocation_only;
ALTER TABLE admin.admin_tenant   DISABLE TRIGGER admin_tenant_revocation_only;

UPDATE admin.platform_admin SET expires_at = granted_at + interval '8 hours'
 WHERE expires_at IS NULL;
UPDATE admin.admin_tenant   SET expires_at = granted_at + interval '90 days'
 WHERE expires_at IS NULL;

ALTER TABLE admin.platform_admin ENABLE TRIGGER platform_admin_revocation_only;
ALTER TABLE admin.admin_tenant   ENABLE TRIGGER admin_tenant_revocation_only;

ALTER TABLE admin.platform_admin
    DROP CONSTRAINT platform_admin_expires_after_granted,
    ADD  CONSTRAINT platform_admin_expires_after_granted CHECK (
        expires_at > granted_at);

ALTER TABLE admin.admin_tenant
    DROP CONSTRAINT admin_tenant_expires_after_granted,
    ADD  CONSTRAINT admin_tenant_expires_after_granted CHECK (
        expires_at > granted_at);

ALTER TABLE admin.platform_admin
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN expires_at SET DEFAULT now() + interval '8 hours';

ALTER TABLE admin.admin_tenant
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN expires_at SET DEFAULT now() + interval '90 days';

COMMENT ON COLUMN admin.platform_admin.expires_at IS
'Terme de l''octroi. Toute autorité en porte un : le juste-à-temps.';
COMMENT ON COLUMN admin.admin_tenant.expires_at IS
'Terme de l''octroi. Toute autorité en porte un : le juste-à-temps.';

UPDATE admin.authority_scope SET max_duration = interval '8 hours'
 WHERE scope = 'PLATFORM';
UPDATE admin.authority_scope SET max_duration = interval '90 days'
 WHERE scope = 'TENANT';

ALTER TABLE admin.authority_scope
    DROP CONSTRAINT authority_scope_impersonation_within_authority,
    ADD  CONSTRAINT authority_scope_impersonation_within_authority CHECK (
        max_impersonation <= max_duration);

ALTER TABLE admin.authority_scope
    DROP CONSTRAINT authority_scope_duration_positive,
    ADD  CONSTRAINT authority_scope_duration_positive CHECK (
        max_duration > interval '0');

ALTER TABLE admin.authority_scope
    ALTER COLUMN max_duration SET NOT NULL;

COMMENT ON COLUMN admin.authority_scope.max_duration IS NULL;

RESET ROLE;
