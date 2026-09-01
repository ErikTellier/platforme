-- ═══════════════════════════════════════════════════════════════════════════
--  AMORÇAGE PROPRE AU SERVICE `admin`.
--
--  Joué par `db-init`, en superutilisateur, APRÈS l'amorçage générique et
--  AVANT toute migration. Ce que la migration ne peut pas poser elle-même
--  vient ici — et seulement ça.
--
--  L'amorçage générique (rôles `<base>_owner` et `<base>_migrator`, droits sur
--  la base et sur `public`) est commun à tous les services : il vit dans
--  `db-init`, pas ici. Ce fichier ne porte que ce qui appartient à `admin`.
--
--  Idempotent : rejoué à chaque `docker compose up`.
-- ═══════════════════════════════════════════════════════════════════════════

-- ─── L'EXTENSION ICI, ET PAS DANS LA MIGRATION ───────────────────────────────
--
-- Postgres n'a pas de `ALTER EXTENSION ... OWNER TO` : une extension créée par
-- un compte jetable lui appartient POUR TOUJOURS, et ce compte devient
-- indestructible — donc son bail irrévocable. Créée à l'amorçage, elle
-- appartient à un rôle permanent, et la migration la saute.
CREATE EXTENSION IF NOT EXISTS citext;

-- ─── LES RÔLES APPLICATIFS, POUR UNE AUTRE RAISON ────────────────────────────
--
-- Le mécanisme diffère de celui de l'extension, et vaut d'être écrit parce
-- qu'il a déjà coûté une panne silencieuse.
--
-- `REASSIGN OWNED BY <jetable> TO <owner>` réécrit le DONNEUR des privilèges
-- portés par les objets qu'il transfère : c'est pourquoi tous les GRANT de
-- table et de fonction survivent à la révocation d'un bail.
--
-- UNE APPARTENANCE DE RÔLE N'EST PAS UN OBJET. Elle n'a pas de propriétaire,
-- donc rien ne la réassigne, et le `DROP OWNED BY` qui suit l'emporte. La
-- migration accordait `app_admin_plane` à `admin_app` — et chaque bail de
-- migration révoqué la reprenait, sans bruit. Constaté : `admin_app` membre de
-- rien, aucun droit, et le service ne s'en apercevait pas parce qu'il se
-- connecte par les comptes dynamiques d'OpenBao. Un déploiement sur
-- identifiants statiques, lui, n'aurait eu aucun droit.
--
-- Pire : l'option ADMIN sur `app_admin_plane` appartenait au compte jetable qui
-- l'avait créé. Elle est morte avec lui, et PLUS AUCUNE MIGRATION NE PEUT
-- REPOSER CETTE APPARTENANCE — seul un superutilisateur le peut. C'est donc
-- ici, et nulle part ailleurs.
--
-- Les CREATE de la migration sont gardés par IF NOT EXISTS : les créer d'abord
-- ne lui retire rien, elle continue de leur attacher les droits.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_admin_plane') THEN
    CREATE ROLE app_admin_plane NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin_app') THEN
    CREATE ROLE admin_app LOGIN;
  END IF;
END $$;

-- INHERIT et non SET : le service ne doit pas pouvoir ENDOSSER le rôle,
-- seulement en hériter. Accordée par le superutilisateur, donc par un donneur
-- qu'aucune révocation de bail n'emporte.
GRANT app_admin_plane TO admin_app WITH INHERIT TRUE, SET FALSE;

-- ─── ET L'ADMINISTRATION AU GROUPE DE MIGRATION ──────────────────────────────
--
-- Sans quoi ce qui précède casse la migration au lieu de la réparer.
--
-- Depuis PostgreSQL 16, CREATEROLE ne suffit plus : on ne peut modifier que les
-- rôles dont on a l'ADMIN. Créer ces deux-là ici les retire donc à la
-- migration, qui échoue sur « permission denied to grant role » à la ligne
-- suivante, puis sur ses ALTER ROLE de délais. La panne est frontale et
-- immédiate — c'est la seule bonne nouvelle de l'affaire.
--
-- INHERIT FALSE ET SET FALSE, délibérément. Le compte de migration doit pouvoir
-- ADMINISTRER ces rôles ; il ne doit ni recevoir les privilèges du service, ni
-- pouvoir se faire passer pour lui. Administrer n'est pas endosser, et la
-- différence est exactement ce qui sépare celui qui pose la carte des droits de
-- celui qui s'en sert.
GRANT app_admin_plane, admin_app TO admin_migrator
  WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
