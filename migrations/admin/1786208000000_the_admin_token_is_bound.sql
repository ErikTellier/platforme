-- Up Migration

-- LE PLAN PRIVILÉGIÉ ÉTAIT MOINS PROTÉGÉ QUE LE PLAN UTILISATEUR.
--
--     auth.session   : aal_code, cnf_jkt
--     admin.session  : —
--
-- `auth` sait dire « ce jeton n'est utilisable que par le porteur qui l'a
-- demandé » : `cnf_jkt` est l'empreinte de la clé de preuve de possession, et
-- un jeton volé sans elle ne vaut rien. `admin` ne savait même pas le
-- représenter. Ses jetons sont des porteurs simples.
--
-- L'inversion est nette : la base qui a pouvoir sur tous les clients porte le
-- lien le plus faible. Elle était atténuée par la fenêtre courte — cinq minutes
-- de porteur, quinze d'inactivité, une heure de plafond — et par la clé
-- matérielle sur les actions lourdes. Mais « atténuée » veut dire qu'un jeton
-- volé sert quand même, quelques minutes, à tout ce qui n'est pas lourd : lire
-- la liste des clients, la carte des autorités, le journal.
--
--
-- ═══ UNE EMPREINTE, PAS UNE CLÉ ═══
--
-- `cnf_jkt` est le SHA-256 de la clé publique du porteur, encodé base64url —
-- 43 caractères. La base ne stocke jamais de clé : elle stocke de quoi vérifier
-- que celle présentée est la même. C'est exactement ce que fait `auth`, et
-- c'est la même contrainte de forme, pour que les deux plans se lisent pareil.
--
--
-- ═══ IMMUABLE, POUR LA MÊME RAISON QUE LE NIVEAU D'ASSURANCE ═══
--
-- `auth` refuse (`AU042`) qu'une session change de clé de liaison en cours de
-- route : la relier après coup rendrait rétroactivement légitimes tous les
-- jetons déjà émis. Ici c'est pareil, et le mécanisme aussi — on ouvre une
-- NOUVELLE session, on ne repeint pas l'ancienne.
--
--
-- ═══ FACULTATIF, ET C'EST LE SEUL POINT DISCUTABLE ═══
--
-- La colonne est nullable. Une session sans liaison reste possible, parce que
-- l'exiger tout de suite rendrait la base inutilisable par un client qui ne
-- sait pas encore faire de DPoP — et une contrainte qu'on désactive en
-- production n'est pas une contrainte.
--
-- Ce que la base garantit donc : si une session DÉCLARE une liaison, cette
-- liaison ne bouge plus. Ce qui reste à la bordure : refuser d'ouvrir une
-- session d'administration sans liaison. La vue `admin.unbound_session` existe
-- pour que « combien de sessions d'administration ne sont pas liées » soit une
-- question à réponse chiffrée, plutôt qu'une intention.
--
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD014  the binding key of a session is immutable
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

ALTER TABLE admin.session
    ADD COLUMN cnf_jkt text;

ALTER TABLE admin.session
    ADD CONSTRAINT session_cnf_jkt_shape CHECK (
        cnf_jkt IS NULL OR cnf_jkt ~ '^[A-Za-z0-9_-]{43}$');

COMMENT ON COLUMN admin.session.cnf_jkt IS
'Empreinte SHA-256 de la clé publique du porteur, base64url — la liaison qui
rend un jeton d''administration inutilisable par qui le vole. Le plan
utilisateur l''avait, le plan privilégié non : l''inversion exacte du modèle de
menace. Nullable, parce qu''une contrainte qu''on désactive en production n''en
est pas une ; ce qui est garanti, c''est qu''une liaison DÉCLARÉE ne bouge
plus.';


CREATE FUNCTION admin.session_binding_is_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.cnf_jkt IS DISTINCT FROM OLD.cnf_jkt THEN
        RAISE EXCEPTION 'the binding key of a session is immutable'
            USING ERRCODE = 'AD014',
                  HINT = 'Open a NEW session. Re-binding an existing one would '
                         'retroactively legitimise every token already issued '
                         'against it.';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.session_binding_is_immutable() FROM PUBLIC;

CREATE TRIGGER session_binding_is_immutable
    BEFORE UPDATE ON admin.session
    FOR EACH ROW EXECUTE FUNCTION admin.session_binding_is_immutable();


-- Ce qu'on mesure plutôt que ce qu'on espère : combien de sessions
-- d'administration tournent sans liaison, en ce moment.
CREATE VIEW admin.unbound_session
    WITH (security_invoker = TRUE)
AS
SELECT s.id, s.user_id, s.created_at, s.absolute_expires_at
  FROM admin.session AS s
 WHERE s.cnf_jkt IS NULL
   AND s.ended_at IS NULL
   AND now() < s.absolute_expires_at;

COMMENT ON VIEW admin.unbound_session IS
'Les sessions d''administration qu''un jeton volé suffirait à reprendre. La
liaison est facultative en base et obligatoire à la bordure : cette vue est ce
qui empêche « obligatoire à la bordure » de rester une phrase.';

CREATE VIEW api.unbound_session AS
  SELECT id, user_id, created_at, absolute_expires_at
    FROM admin.unbound_session;
GRANT SELECT ON api.unbound_session TO app_admin_plane;

-- La vue que l'application lit porte la colonne, sinon la liaison existe et
-- personne ne peut l'écrire — le trou exact qu'`api.identity` avait avec
-- `connection_id`.
CREATE OR REPLACE VIEW api.session AS
  SELECT id, user_id, created_at, absolute_expires_at, ended_at, end_reason,
         cnf_jkt
    FROM admin.session;

GRANT UPDATE (cnf_jkt) ON api.session TO app_admin_plane;

INSERT INTO audit.auditable_column (schema_name, table_name, column_name)
VALUES ('admin', 'session', 'cnf_jkt');

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name = 'session'
   AND column_name = 'cnf_jkt';

DROP VIEW api.unbound_session;
DROP VIEW admin.unbound_session;

-- DROP puis CREATE, parce que remplacer une vue ne sait pas RETIRER une
-- colonne. Il faut donc reposer les droits — et les DEUX, pas seulement celui
-- qu'on a sous les yeux : le droit de colonne sur `ended_at, end_reason` est ce
-- qui permet de fermer une session, et l'oublier ne se voit qu'au test.
DROP VIEW api.session;
CREATE VIEW api.session AS
  SELECT id, user_id, created_at, absolute_expires_at, ended_at, end_reason
    FROM admin.session;
GRANT SELECT, INSERT ON api.session TO app_admin_plane;
GRANT UPDATE (ended_at, end_reason) ON api.session TO app_admin_plane;

DROP TRIGGER session_binding_is_immutable ON admin.session;
DROP FUNCTION admin.session_binding_is_immutable();

ALTER TABLE admin.session DROP CONSTRAINT session_cnf_jkt_shape;
ALTER TABLE admin.session DROP COLUMN cnf_jkt;

RESET ROLE;
