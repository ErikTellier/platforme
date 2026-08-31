-- Up Migration

-- ON VÉRIFIAIT TOUT DE L'OCTROI, ET RIEN DE CELUI QUI LE SIGNE.
--
-- `authority_grant_guard` contrôle le bénéficiaire (AD070), la politique du
-- périmètre (AD078), la durée (AD073), l'auto-octroi (AD074), le second
-- approbateur (AD075) et le bris de glace (AD076). Six refus, tous sur le
-- CONTENU de l'octroi.
--
-- Aucun ne regarde `granted_by`.
--
-- Tant que les seuls admins sont ceux qui écrivent la base, c'est théorique.
-- Ça cesse de l'être dès qu'un `admin_tenant` est un administrateur CHEZ LE
-- CLIENT : rien n'empêche alors l'admin du client A d'accorder une autorité
-- sur le client B. AD074 lui interdit de se servir lui-même — il sert son
-- collègue, qui le sert en retour. La règle des quatre yeux tient, et la
-- frontière entre deux clients ne tient pas.
--
-- Le même trou côté `revoked_by` : neutraliser les administrateurs d'un
-- concurrent est un geste plus discret que s'accorder ses droits, et il ne
-- rencontrait rien non plus.
--
--
-- ═══ CE N'EST PAS LA CIRCULARITÉ QUE L'AXIOME INTERDIT ═══
--
-- `admin` qui interroge `admin` est de la cohérence interne. L'axiome porte
-- sur IAM : « l'autorité d'un admin ne dérive pas d'IAM, elle la précède ».
-- Il n'y a aucun appel à `iam` ici, et il ne peut pas y en avoir — ce sont
-- deux bases, et `check-autonomy` le prouve à chaque exécution.
--
-- La lecture se fait par `admin.effective_authority` et non par une requête
-- écrite pour l'occasion : c'est déjà la vue qui répond à « qui peut opérer,
-- maintenant » à l'écran. Deux lectures de la même question finissent par
-- diverger, et le jour où elles divergent c'est la garde qui a tort.
--
-- Elle est plus stricte que `may_operate` sur un point : elle joint
-- `admin."user"` et écarte les comptes désactivés. Un admin désactivé dont
-- l'octroi court encore ne signe plus rien.
--
--
-- ═══ CE QUE CETTE GARDE NE VÉRIFIE PAS, ET POURQUOI ═══
--
-- `approved_by` — le second approbateur — n'a PAS à détenir l'autorité.
-- L'exiger paraissait évident, et rend le modèle inatteignable :
--
--   · la genèse n'exempte qu'UNE ligne, celle qui trouve la table vide ;
--   · pour un deuxième admin de plateforme il faudrait alors un signataire
--     ET un approbateur déjà en autorité, soit deux — alors qu'il n'en
--     existe qu'un ;
--   · AD075 exige en plus qu'ils soient distincts.
--
-- Le second admin de plateforme ne serait jamais accordable. Une garde qui
-- rend impossible l'état normal du système n'est pas stricte, elle est
-- fausse. AD075 continue d'exiger une seconde personne DISTINCTE : c'est un
-- témoin, pas un co-détenteur.
--
--
-- ═══ LE PREMIER ADMIN N'A PERSONNE POUR L'ACCORDER ═══
--
-- Poule et œuf, et il n'y a pas de réponse élégante — seulement une réponse
-- dont la portée est bornée.
--
-- L'exemption vaut quand `admin.platform_admin` est VIDE. Pas « quand aucun
-- octroi n'est vivant » : le périmètre PLATFORM est plafonné à huit heures,
-- donc la plateforme passe ses nuits et ses week-ends sans admin vivant, et
-- une exemption écrite comme ça serait ouverte la plupart du temps — un
-- administrateur de client attendrait trois heures du matin pour accorder à
-- son collègue l'autorité de plateforme. Vide veut dire vide, et la table
-- refuse la suppression (AD071) : la condition est vraie une seule fois dans
-- la vie de la base.
--
-- Et même là, AD074 s'applique : l'amorçage demande deux personnes. On ne se
-- fabrique pas administrateur tout seul, même le premier jour.
--
-- `admin_tenant` n'a AUCUNE exemption. Le jour où l'on accorde le premier
-- administrateur d'un client, la plateforme a nécessairement des admins.
--
--
-- ═══ CE QUI SE PASSE SI TOUT EXPIRE EN MÊME TEMPS ═══
--
-- Plus personne ne peut accorder. C'est la contrepartie assumée, et elle a
-- une règle d'exploitation : LES TERMES SE CHEVAUCHENT. Un octroi PLATFORM
-- dure huit heures, soit une garde ; on ré-accorde avant l'échéance, pas
-- après. C'est le fonctionnement normal d'une astreinte.
--
-- Si le trou survient quand même, la sortie est celle que le contrat annonce
-- déjà pour le tout premier admin : un opérateur écrit la ligne en direct,
-- déclencheur désactivé, avec les droits du propriétaire du schéma. Ce n'est
-- pas une porte dérobée — qui a ces droits-là peut déjà tout — mais c'est un
-- geste qui laisse une trace et qu'on ne fait pas par distraction.
--
--
-- ═══ LA GARDE LIT `now()`, ET C'EST UN CHOIX ═══
--
-- Un octroi est jugé sur l'autorité que son signataire a AU MOMENT DE
-- SIGNER. Lire l'autorité à `granted_at` serait plus fidèle à l'histoire,
-- mais `granted_at` est fourni par l'appelant à l'insertion : ce serait
-- offrir une élévation à qui sait antidater. La fidélité historique se paie
-- ici en trou de sécurité, donc on garde `now()`.
--
-- Conséquence assumée : on ne rejoue pas un historique d'octrois signés par
-- quelqu'un dont l'autorité a depuis expiré. Le semis en tient compte.
--
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD079  the signer holds no live authority over this perimeter
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- La question « cette personne peut-elle signer ici, maintenant » se pose à
-- quatre endroits. Une fonction plutôt que quatre sous-requêtes recopiées :
-- recopiée, elle se serait mise à diverger au premier ajustement.
CREATE FUNCTION admin.signs_here(p_user uuid, p_tenant uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO ''
AS $$
  SELECT EXISTS (
    SELECT FROM admin.effective_authority e
     WHERE e.user_id = p_user
       AND (e.scope = 'PLATFORM'
            OR (p_tenant IS NOT NULL AND e.tenant_id = p_tenant))
  );
$$;

COMMENT ON FUNCTION admin.signs_here IS
'La MÊME lecture que l''écran : `effective_authority`, donc non révoqué, non
expiré, et titulaire actif. `may_operate` ne regarde pas la désactivation du
compte — pour signer un octroi, elle compte. Une portée PLATFORM signe partout ;
une portée TENANT ne signe que chez elle, et jamais un octroi de plateforme.';


CREATE FUNCTION admin.signer_has_authority()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    -- TG_ARGV[0] : 'PLATFORM' ou 'TENANT'.
    -- TG_ARGV[1] : 'GRANT' ou 'REVOKE' — quelle signature on vérifie.
    v_scope   text := TG_ARGV[0];
    v_moment  text := TG_ARGV[1];
    v_signer  uuid;
    v_tenant  uuid;
    v_role    text;
BEGIN
    IF v_moment = 'REVOKE' THEN
        -- Rien à vérifier tant que la révocation n'est pas posée. Le reste des
        -- colonnes est déjà scellé par `authority_revocation_only`.
        IF NEW.revoked_at IS NULL OR OLD.revoked_at IS NOT NULL THEN
            RETURN NEW;
        END IF;
        v_signer := NEW.revoked_by;
        v_role   := 'revoked_by';

        -- UNE RÉVOCATION SANS AUTEUR N'EST PAS UN PROBLÈME D'AUTORITÉ. La
        -- contrainte `revocation_complete` le dit déjà, et mieux : « la date
        -- et l'auteur vont ensemble ». Répondre AD079 ici masquerait un 23514
        -- plus précis derrière un refus de sécurité qui décrit autre chose.
        IF v_signer IS NULL THEN
            RETURN NEW;
        END IF;
    ELSE
        v_signer := NEW.granted_by;
        v_role   := 'granted_by';
    END IF;

    IF v_scope = 'TENANT' THEN
        v_tenant := NEW.tenant_id;
    ELSE
        v_tenant := NULL;

        -- LA GENÈSE. Voir l'entête : la table est en ajout seul, donc « vide »
        -- n'arrive qu'une fois dans la vie de la base.
        IF NOT EXISTS (SELECT FROM admin.platform_admin) THEN
            RETURN NEW;
        END IF;
    END IF;

    IF NOT admin.signs_here(v_signer, v_tenant) THEN
        RAISE EXCEPTION
            'the % of this authority holds none over that perimeter', v_role
            USING ERRCODE = 'AD079',
                  HINT = 'Authority is granted, and revoked, by someone who '
                         'already holds it — live, over the same perimeter. '
                         'A lapsed or revoked grant signs nothing.';
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION admin.signer_has_authority IS
'On vérifiait tout de l''octroi et rien de qui le signe. Sans cette garde,
l''administrateur d''un client peut accorder — ou révoquer — une autorité sur
un AUTRE client. AD074 interdit de se servir soi-même, pas de se servir
mutuellement.';


-- Postgres accorde EXECUTE à PUBLIC sur toute fonction créée. Sur une fonction
-- DEFINER, ça remet les droits du propriétaire à TOUS les rôles du cluster —
-- et celle-ci lit l'autorité d'administration. Deux lignes, non négociables.
REVOKE EXECUTE ON FUNCTION admin.signer_has_authority() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.signs_here(uuid, uuid) FROM PUBLIC;

CREATE TRIGGER platform_admin_signer_has_authority
    BEFORE INSERT ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.signer_has_authority('PLATFORM', 'GRANT');

CREATE TRIGGER platform_admin_revoker_has_authority
    BEFORE UPDATE ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.signer_has_authority('PLATFORM', 'REVOKE');

CREATE TRIGGER admin_tenant_signer_has_authority
    BEFORE INSERT ON admin.admin_tenant
    FOR EACH ROW EXECUTE FUNCTION admin.signer_has_authority('TENANT', 'GRANT');

CREATE TRIGGER admin_tenant_revoker_has_authority
    BEFORE UPDATE ON admin.admin_tenant
    FOR EACH ROW EXECUTE FUNCTION admin.signer_has_authority('TENANT', 'REVOKE');

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP TRIGGER admin_tenant_revoker_has_authority ON admin.admin_tenant;
DROP TRIGGER admin_tenant_signer_has_authority ON admin.admin_tenant;
DROP TRIGGER platform_admin_revoker_has_authority ON admin.platform_admin;
DROP TRIGGER platform_admin_signer_has_authority ON admin.platform_admin;

DROP FUNCTION admin.signer_has_authority();
DROP FUNCTION admin.signs_here(uuid, uuid);

RESET ROLE;
