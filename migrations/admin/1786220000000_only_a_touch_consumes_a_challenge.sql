-- Up Migration

-- LE PLAN PEUT DEMANDER UNE PREUVE, JAMAIS LA DÉCLARER OBTENUE.
--
-- `api.challenge` a été écrite avant que `scope` et `target_tenant_id`
-- n'existent, et sa liste de colonnes a été figée là. Résultat : `scope` étant
-- NOT NULL sans défaut, le plan ne peut insérer AUCUN défi — pas par politique,
-- par forme de vue. Le travail FIDO2 exige d'y remédier.
--
-- Or l'ouvrir telle quelle rendrait vivant un défaut jusque-là inoffensif.
--
--
-- ═══ LE DÉFAUT, ET POURQUOI IL COMPTE PLUS QUE TOUT LE RESTE ═══
--
-- `GRANT INSERT ON api.challenge` est accordé AU NIVEAU DE LA TABLE, donc sur
-- toutes ses colonnes — `consumed_at` comprise. Un plan qui peut écrire un défi
-- DÉJÀ CONSOMMÉ peut produire une commande signée sans qu'aucune clé matérielle
-- n'ait été touchée.
--
-- Toute la couche de présence deviendrait décorative : `verify_presence` resterait
-- le chemin honnête, et il y en aurait un autre. C'est exactement la forme de
-- défaut que ce schéma traque partout ailleurs — une garantie qui se lit vraie.
--
-- Elle ne l'était pas encore, faute de pouvoir insérer du tout. Elle le
-- deviendrait à la ligne près qui débloque l'enrôlement.
--
--
-- ═══ POURQUOI RÉVOQUER EN ENTIER PUIS RE-ACCORDER ═══
--
-- On ne retire pas une colonne d'un privilège accordé au niveau de la table.
-- `REVOKE INSERT (consumed_at)` ne fait rien d'utile ici : le privilège de table
-- subsiste et continue de couvrir la colonne. PostgreSQL n'échoue pas, il ne
-- retire simplement rien — le pire des deux, puisque la migration paraît avoir
-- réussi.
--
-- Le privilège de table tombe donc en entier, et il est ré-accordé colonne par
-- colonne. Ce qui n'est pas nommé n'est pas écrit :
--
--   `consumed_at`  ne bouge que par `verify_presence`, qui exige une assertion.
--   `id`, `created_at`  ont un défaut ; les accorder n'apporte que la possibilité
--                       de les contredire.
--
-- Même discipline que `api.key`, dont l'INSERT a toujours été une liste explicite.
--
--
-- ═══ LA SYMÉTRIE AVEC L'AUTHENTIFICATEUR, QUI EST DÉJÀ JUSTE ═══
--
-- `api.authenticator` accorde INSERT sur `sign_count` — c'est légitime, le
-- compteur initial se pose à l'enrôlement — mais PAS UPDATE : « granting
-- sign_count here would allow the counter to be moved without an assertion ».
-- La même phrase vaut ici pour `consumed_at`, un cran plus haut.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code. Une écriture non accordée est refusée par le moteur en 42501,
--   avant qu'aucun déclencheur ne s'exécute.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- CREATE OR REPLACE sait ajouter en queue : les colonnes existantes gardent leur
-- nom, leur ordre et leur type, donc rien de ce qui lit déjà ne bouge.
CREATE OR REPLACE VIEW api.challenge AS
  SELECT id, user_id, session_id, challenge, action, created_at, expires_at,
         consumed_at, scope, target_tenant_id
    FROM webauthn.challenge;

COMMENT ON VIEW api.challenge IS
'Les défis de présence, tels que le plan peut les voir et les poser. Il peut en
DEMANDER un — user_id, session_id, challenge, action, scope, target_tenant_id,
expires_at — et jamais déclarer qu''il a été obtenu : consumed_at n''est pas
accordée à l''écriture, et ne bouge que par webauthn.verify_presence, qui exige une
assertion d''authentificateur.';

-- Le privilège de table tombe EN ENTIER : une révocation de colonne le laisserait
-- intact et ne retirerait rien.
REVOKE INSERT ON api.challenge FROM app_admin_plane;

GRANT INSERT (user_id, session_id, challenge, action, expires_at,
              scope, target_tenant_id)
  ON api.challenge TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

REVOKE INSERT ON api.challenge FROM app_admin_plane;
GRANT INSERT ON api.challenge TO app_admin_plane;

-- Rétrécir une vue exige de la détruire, donc de reposer TOUS ses droits.
DROP VIEW api.challenge;
CREATE VIEW api.challenge AS
  SELECT id, user_id, session_id, challenge, action, created_at, expires_at,
         consumed_at
    FROM webauthn.challenge;
GRANT SELECT, INSERT, DELETE ON api.challenge TO app_admin_plane;

RESET ROLE;
