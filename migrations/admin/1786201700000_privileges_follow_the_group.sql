-- Up Migration

-- UN PRIVILÈGE ACCORDÉ AU RÔLE DE CONNEXION NE SE RETIRE PLUS.
--
-- ET LE GROUPE NE S'APPELLE PAS TOUJOURS app_<base>. Ma première version l'a
-- déduit du nom de la base et a visé `app_admin` — qui appartient à AUTH et
-- signifie « approvisionnement de auth ». Le schéma initial de cette base
-- l'écrit noir sur blanc : les rôles Postgres sont globaux au cluster, et deux
-- bases partageant un nom de rôle fusionnent silencieusement deux cartes de
-- droits. J'ai fait exactement ce contre quoi le commentaire prévenait.
--
-- Le contrôle d'autonomie l'a arrêté : sur un serveur où seul `admin` tourne,
-- `app_admin` n'existe pas — parce qu'il n'a jamais été à lui.
--
-- Cette base sépare deux rôles : `app_admin_plane` est un groupe NOLOGIN qui PORTE
-- les privilèges, `admin_app` est le rôle applicatif qui s'y connecte et en
-- HÉRITE. Toutes les tables d'origine accordent au groupe.
--
-- Les objets ajoutés au cours des dernières migrations accordent au rôle de
-- connexion. Ça marche — l'application lit ce qu'elle doit lire — et ça casse
-- deux choses en silence :
--
--   1. LA RÉVOCATION. Sortir `admin_app` de `app_admin_plane` est censé lui retirer
--      tout. Les droits posés directement sur lui survivent. On croit avoir
--      coupé un accès, il est toujours là.
--
--   2. LA ROTATION. Un second rôle de connexion — une instance de plus, un
--      identifiant renouvelé, un service de lecture — entre dans le groupe et
--      n'hérite de rien. La panne se manifeste en production, sur les objets
--      les plus récents, c'est-à-dire les moins bien connus.
--
-- Aucune des deux ne se voit à la lecture du code : les deux noms se
-- ressemblent, et la requête fonctionne. Il fallait interroger le catalogue.
-- La règle de doctrine `privileges-follow-the-group` s'en charge désormais.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

DO $$
DECLARE r record; moved int := 0;
BEGIN
    FOR r IN
        SELECT n.nspname, c.relname, a.privilege_type
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          CROSS JOIN LATERAL aclexplode(c.relacl) a
         WHERE c.relkind IN ('r', 'v', 'p')
           AND a.grantee = 'admin_app'::regrole
    LOOP
        EXECUTE format('REVOKE %s ON %I.%I FROM admin_app',
                       r.privilege_type, r.nspname, r.relname);
        EXECUTE format('GRANT %s ON %I.%I TO app_admin_plane',
                       r.privilege_type, r.nspname, r.relname);
        moved := moved + 1;
    END LOOP;
    RAISE NOTICE '% privilege(s) moved from admin_app to app_admin_plane', moved;
END $$;

-- Down Migration

-- Rien. Remettre les privilèges sur le rôle de connexion recréerait le défaut,
-- et une rétrogradation n'a pas à restaurer un trou. Les objets restent
-- lisibles par admin_app à travers son appartenance au groupe : du point de
-- vue de l'application, rien n'a changé dans un sens comme dans l'autre.
SELECT 1;
