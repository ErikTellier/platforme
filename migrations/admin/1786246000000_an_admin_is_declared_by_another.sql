-- Up Migration

-- UN ADMINISTRATEUR EST DÉCLARÉ PAR UN AUTRE, ET ÇA SE PROUVE.
--
-- ═══ LE SEUL ACTE DU PLAN QUI N'AVAIT AUCUN CHEMIN ═══
--
-- `the_first_admin_is_declared` a posé la propriété : « an admin is explicitly
-- declared, never self-created ». Elle est tenue par l'absence : `admin."user"`
-- porte une ACL VIDE, et `api."user"` n'accorde que SELECT et l'`UPDATE` de
-- `deactivated_at`. Le plan ne peut donc pas créer d'administrateur — et n'a
-- jamais pu.
--
-- Ce qui laissait un seul chemin réel : quelqu'un ouvre psql en production. Le
-- geste le plus sensible de la plateforme — faire entrer une personne dans le
-- plan de contrôle — était le seul qui n'apparaissait dans AUCUN journal de
-- commandes. `identity.provision` est au vocabulaire depuis le premier jour,
-- portée PLATFORM, et rien ne l'émettait.
--
-- ═══ CE QUE LA PROPRIÉTÉ DEVIENT ═══
--
-- Elle ne change pas, elle se déplace. Le plan ne peut toujours pas écrire
-- `admin."user"` : l'ACL reste vide et `api."user"` n'accorde aucun INSERT. Il
-- appelle une FONCTION ATOMIQUE, comme pour les tickets d'enrôlement, les
-- paires et les preuves — et cette fonction exige de savoir QUI déclare et SUR
-- QUELLE COMMANDE.
--
-- « Se déclare hors-bande » devient donc « se déclare par une commande signée »,
-- ce qui est strictement plus fort : une touche matérielle, un administrateur
-- nommé, et une ligne dans `signed_command` que l'ajout seul empêche d'effacer.
--
-- ═══ POURQUOI UNE FONCTION, ET PAS DEUX INSERT ═══
--
-- Un `admin."user"` sans `admin.identity` est un FANTÔME : il ne correspond à
-- personne chez le fournisseur, personne ne peut s'y connecter, et rien ne le
-- distingue d'un compte qu'on aurait oublié de finir. La fonction écrit les deux
-- ou aucune.
--
-- `api.identity` porte pourtant déjà un INSERT au plan. Il reste — il sert à
-- ajouter une seconde identité à un utilisateur qui existe — mais il ne peut pas
-- servir à en créer un, faute d'utilisateur à citer.
--
-- ═══ IL N'Y A PAS DE « PAS POUR SOI-MÊME » ICI, ET C'EST NORMAL ═══
--
-- Les autres actes en ont un — `authority_request_not_for_oneself`,
-- `operator_residency_not_for_oneself` — parce qu'ils NOMMENT un sujet qui
-- existe déjà. Ici le sujet est CRÉÉ par l'acte, et son identifiant vient du
-- défaut de la colonne : il n'existe aucune façon de désigner une personne
-- existante comme bénéficiaire. Écrire la contrainte quand même donnerait une
-- garde qui ne peut jamais parler, et le dépôt en a assez d'une qui parle mal.
--
-- ═══ ET AUCUNE AUTORITÉ N'EST ACCORDÉE ═══
--
-- Provisionner ne donne RIEN. La personne existe, pourra enrôler une clé et se
-- connecter, et ne pourra rien faire : l'autorité vit dans `platform_admin` et
-- `admin_tenant`, derrière la cérémonie à quatre yeux. Ce n'est pas une
-- politique posée ici, c'est une conséquence — cette fonction n'a aucun
-- privilège sur ces tables.
--
-- ═══ QUI PEUT APPELER : LA BASE LE TIENT DÉJÀ ═══
--
-- Rien à écrire. `identity.provision` est de portée PLATFORM, donc le défi qui
-- fonde la commande est frappé sans client. `verify_presence` relit
-- `may_operate(user, NULL)`, qui se réduit alors à « détient une autorité de
-- PLATEFORME vivante » — la branche `admin_tenant` ne peut pas s'apparier à un
-- client nul. Un administrateur de client ne peut donc pas consommer cette
-- présence, et sans elle il n'y a pas de commande.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   AD051  la commande de provisionnement n'est pas ce provisionnement, par
--          son auteur — ou l'auteur et la commande n'ont pas été nommés
--   23505  `uq_identity_provider_id` : ce compte du fournisseur est déjà
--          déclaré. Provisionner deux fois la même personne est un doublon,
--          pas un second administrateur
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

ALTER TABLE admin."user"
    ADD COLUMN provisioned_by       uuid,
    ADD COLUMN provision_command_id uuid;

ALTER TABLE admin."user"
    ADD CONSTRAINT user_provisioned_by_fk
        FOREIGN KEY (provisioned_by) REFERENCES admin."user" (id) ON DELETE RESTRICT;

ALTER TABLE admin."user"
    ADD CONSTRAINT user_provision_command_fk
        FOREIGN KEY (provision_command_id)
        REFERENCES admin.signed_command (id) ON DELETE RESTRICT;

-- L'AUTEUR ET SA PREUVE VONT ENSEMBLE. Même forme que
-- `authority_request_approval_complete` : l'un sans l'autre décrirait un acte
-- dont on connaît la moitié.
ALTER TABLE admin."user"
    ADD CONSTRAINT user_provisioning_complete CHECK (
        (provisioned_by IS NULL) = (provision_command_id IS NULL));

COMMENT ON COLUMN admin."user".provisioned_by IS
'L''administrateur qui a déclaré celui-ci. NUL pour la genèse seule — les
migrations d''amorçage déclarent le premier, qui n''a personne au-dessus de lui.';

COMMENT ON COLUMN admin."user".provision_command_id IS
'La commande `identity.provision` qui l''a déclaré. Faire entrer une personne
dans le plan de contrôle est le geste le plus sensible de la plateforme ; il ne
s''écrivait jusqu''ici dans aucun journal de commandes.';


-- ═══ LA MÊME EXIGENCE QUE LES TROIS AUTRES ACTES ═══
--
-- Les quatre égalités de `request_is_signed`, moins la cible : la portée est
-- PLATFORM par le vocabulaire, donc le client est toujours nul.

CREATE FUNCTION admin.user_is_signed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    -- LA GENÈSE, et elle seule. `user_provisioning_complete` garantit que
    -- l'auteur nul va avec une commande nulle, et le plan n'a aucun chemin qui
    -- laisse les deux vides — `provision_admin` les exige.
    IF NEW.provisioned_by IS NULL THEN
        RETURN NEW;
    END IF;

    PERFORM FROM admin.signed_command c
     WHERE c.id = NEW.provision_command_id
       AND c.action = 'identity.provision'
       AND c.scope = 'PLATFORM'
       AND c.user_id = NEW.provisioned_by;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'the provision command is not this provisioning, by %',
            NEW.provisioned_by
            USING ERRCODE = 'AD051',
                  HINT = 'An administrator is declared by another, who touched '
                         'their own key for it. Recycling someone else''s '
                         'command is what this refuses.';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.user_is_signed() FROM PUBLIC;

CREATE TRIGGER user_is_signed
    BEFORE INSERT ON admin."user"
    FOR EACH ROW EXECUTE FUNCTION admin.user_is_signed();


-- ═══ LA PORTE DU PLAN ═══
--
-- `SECURITY DEFINER` parce que `admin."user"` a une ACL VIDE et doit la garder :
-- c'est elle qui fait que « le plan ne s'enrôle pas lui-même » n'est pas une
-- politique mais une impossibilité. La fonction est le seul chemin, et elle
-- exige ce qu'un INSERT nu ne saurait pas exiger.

CREATE FUNCTION admin.provision_admin(
    p_provider         text,
    p_provider_id      text,
    p_provisioned_by   uuid,
    p_command_id       uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_user uuid;
BEGIN
    -- LES DEUX SONT EXIGÉS ICI, et pas seulement par le déclencheur. Celui-ci
    -- laisse passer l'auteur nul — c'est la genèse — et une fonction qui
    -- transmettrait des nuls ouvrirait cette porte au plan.
    IF p_provisioned_by IS NULL OR p_command_id IS NULL THEN
        RAISE EXCEPTION 'provisioning names its author and its command'
            USING ERRCODE = 'AD051',
                  HINT = 'The genesis is a migration, not a route.';
    END IF;

    INSERT INTO admin."user" (provisioned_by, provision_command_id)
    VALUES (p_provisioned_by, p_command_id)
    RETURNING id INTO v_user;

    -- L'IDENTITÉ NAÎT LIÉE. `identity_bind_once` estampille `bound_at` dès
    -- l'insertion quand `provider_id` est présent, et
    -- `identity_provider_or_provision` accepte cette forme depuis le premier
    -- jour. C'est ce que rend un annuaire interrogé : l'`oid`, tout de suite.
    --
    -- Donc PAS de `provision_key` : l'UPN n'est jamais écrit, même
    -- temporairement. Le commentaire de la colonne le décrit comme « EPHEMERAL
    -- PII » — ici il n'existe pas du tout.
    INSERT INTO admin.identity (user_id, provider, provider_id)
    VALUES (v_user, p_provider, p_provider_id);

    RETURN v_user;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.provision_admin(text, text, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.provision_admin(text, text, uuid, uuid) TO app_admin_plane;

COMMENT ON FUNCTION admin.provision_admin IS
'Déclare un administrateur : l''utilisateur et son identité, ou aucun des deux.
Un utilisateur sans identité est un fantôme — personne ne peut s''y connecter, et
rien ne le distingue d''un compte qu''on a oublié de finir.

Elle n''accorde AUCUNE autorité, et n''en a pas le privilège. La personne existe,
pourra enrôler une clé, et ne pourra rien faire tant que la cérémonie à quatre
yeux ne s''est pas prononcée.';


-- LA VUE APPREND LES DEUX COLONNES. Elle fige sa liste à la création, et
-- `CREATE OR REPLACE` ne sait qu'ajouter à la fin — ce qui suffit et garantit
-- qu'aucune position existante ne bouge.
--
-- EN LECTURE SEULE : l'ACL de `api."user"` accorde `r` au niveau de la table et
-- `w` sur la seule `deactivated_at`. Les colonnes neuves se lisent donc, et ne
-- s'écrivent par aucun chemin du plan.
CREATE OR REPLACE VIEW api."user" AS
SELECT id, created_at, deactivated_at, provisioned_by, provision_command_id
  FROM admin."user";

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

-- DÉTRUIRE PUIS RECRÉER, ET NON `CREATE OR REPLACE`.
--
-- `CREATE OR REPLACE VIEW` sait ajouter une colonne, jamais en retirer :
-- Postgres refuse avec « cannot drop columns from view ». Le retour de cette
-- migration en enlève deux, il ne peut donc pas passer par là. Constaté en
-- exécutant `migrate:down` pour la première fois — ce retour n'avait jamais
-- été joué.
--
-- ET REPOSER LES DROITS. Un `DROP` emporte l'ACL avec l'objet. Sans les deux
-- GRANT qui suivent, la vue revient muette pour `app_admin_plane` : le plan
-- d'administration perdrait la lecture des utilisateurs, et aucune migration
-- n'aurait dit pourquoi. Ces droits sont posés par `initial_schema` ; c'est à
-- ce retour de les rendre, puisque c'est lui qui les détruit.
--
-- Pas de `CASCADE` : rien ne dépendait de cette vue quand ce retour a été
-- écrit, et un CASCADE détruirait en silence ce qu'on n'aurait pas vu venir.
-- S'il échoue un jour sur une dépendance, c'est une information.
DROP VIEW api."user";

CREATE VIEW api."user" AS
SELECT id, created_at, deactivated_at FROM admin."user";

GRANT SELECT ON api."user" TO app_admin_plane;
GRANT UPDATE (deactivated_at) ON api."user" TO app_admin_plane;

DROP FUNCTION admin.provision_admin(text, text, uuid, uuid);

DROP TRIGGER user_is_signed ON admin."user";
DROP FUNCTION admin.user_is_signed();

ALTER TABLE admin."user" DROP CONSTRAINT user_provisioning_complete;
ALTER TABLE admin."user" DROP CONSTRAINT user_provision_command_fk;
ALTER TABLE admin."user" DROP CONSTRAINT user_provisioned_by_fk;
ALTER TABLE admin."user" DROP COLUMN provision_command_id;
ALTER TABLE admin."user" DROP COLUMN provisioned_by;

RESET ROLE;
