-- Up Migration

-- UNE VUE DESSINÉE AVANT D'AVOIR UN LECTEUR EST UNE VUE DESSINÉE AU HASARD.
--
-- `akeys.signing_material` existe depuis le premier jour et personne ne l'a
-- jamais lue : l'application garde `kms_ref` en mémoire depuis la frappe, à la
-- connexion. Sa forme n'a donc jamais été confrontée à une question réelle.
--
-- La rotation du refresh est ce premier lecteur. Elle doit re-signer une paire
-- avec la clé de LA SESSION qu'elle fait tourner, et ce qu'elle tient est un
-- identifiant de session : `rotate_pair` rend `session_id`, pas `user_id`.
--
--
-- ═══ POURQUOI PAS SIMPLEMENT JOINDRE SUR user_id ═══
--
-- Ça marcherait. `uq_session_mono` n'admet qu'une session non close par
-- administrateur, et la vue ne montre que les clés dont la session est ouverte
-- depuis `a_second_login_needs_a_second_key` : la clé rendue pour un `user_id`
-- EST donc celle de sa session vivante.
--
-- Mais cette phrase est le raisonnement que l'appelant doit tenir, et refaire, à
-- chaque fois qu'il écrit la requête. Elle repose sur deux index et une jointure
-- de vue qu'il faut être allé lire. Le jour où la mono-session est desserrée —
-- ce que rien n'interdit, elle a déjà été déplacée une fois — la requête devient
-- fausse sans qu'une ligne de son texte ait changé.
--
-- La colonne supprime le raisonnement. On demande par session parce qu'on tient
-- une session.
--
--
-- ═══ EN QUEUE, ET LE MIROIR AUSSI ═══
--
-- `CREATE OR REPLACE VIEW` ne sait qu'AJOUTER, et seulement à la fin : les
-- colonnes existantes gardent leur nom, leur ordre et leur type, donc les droits
-- sont conservés et rien de ce qui lit déjà ne bouge.
--
-- `api.signing_material` doit être remplacée aussi. Elle a été écrite en
-- `SELECT *`, ce qui a figé sa liste de colonnes à la création — le même piège
-- que `a_key_has_one_purpose` a rencontré, pour la même raison.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code. Une colonne de plus ne refuse rien.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE OR REPLACE VIEW akeys.signing_material
    WITH (security_invoker = TRUE)
AS
  SELECT k.id, k.kid, k.user_id, k.kms_ref, k.signs_until, k.purpose,
         k.session_id
    FROM akeys.key AS k
    INNER JOIN admin.session AS s ON k.session_id = s.id
   WHERE k.state = 'ACTIVE'
     AND k.private_destroyed_at IS NULL
     AND now() < k.signs_until
     AND s.ended_at IS NULL;

COMMENT ON COLUMN akeys.signing_material.session_id IS
'De quoi demander par session, puisque c''est une session qu''on tient quand on
fait tourner une paire. Sans elle, l''appelant joint sur user_id et doit savoir
que uq_session_mono rend ça non ambigu — une correction qui vit dans sa tête
plutôt que dans le schéma.';

CREATE OR REPLACE VIEW api.signing_material
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, kms_ref, signs_until, purpose, session_id
    FROM akeys.signing_material;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

-- RÉTRÉCIR une vue exige de la détruire : CREATE OR REPLACE ne sait qu'ajouter.
-- Donc les deux tombent, dans l'ordre des dépendances, et les droits sont
-- reposés à la main — c'est le prix d'un retrait de colonne.
DROP VIEW api.signing_material;
DROP VIEW akeys.signing_material;

CREATE VIEW akeys.signing_material
    WITH (security_invoker = TRUE)
AS
  SELECT k.id, k.kid, k.user_id, k.kms_ref, k.signs_until, k.purpose
    FROM akeys.key AS k
    INNER JOIN admin.session AS s ON k.session_id = s.id
   WHERE k.state = 'ACTIVE'
     AND k.private_destroyed_at IS NULL
     AND now() < k.signs_until
     AND s.ended_at IS NULL;

COMMENT ON VIEW akeys.signing_material IS
'COMMENT signer. La seule voie de lecture de kms_ref — le SELECT sur cette
colonne est révoqué au niveau de la table. Même prédicat que signing_key, la
session comprise : la référence privée d''une clé dont la session est fermée est
inatteignable, comme la clé elle-même a cessé de pouvoir signer. Avec
destroyable_key, kms_ref est lisible exactement deux fois dans la vie d''une
clé — pendant qu''elle signe, et pendant qu''on la détruit.';

CREATE VIEW api.signing_material
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, kms_ref, signs_until, purpose
    FROM akeys.signing_material;

GRANT SELECT ON api.signing_material TO app_admin_plane;

RESET ROLE;
