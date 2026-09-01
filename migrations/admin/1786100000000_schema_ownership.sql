-- Up Migration

-- LES OBJETS N'APPARTIENNENT PLUS À UN SUPERUTILISATEUR.
--
-- SECURITY DEFINER exécute une fonction avec les droits de SON PROPRIÉTAIRE.
-- Tant que ces fonctions appartenaient à `dev`, chacune prêtait le statut de
-- superutilisateur à quiconque pouvait l'appeler : à l'intérieur, RLS, GRANT
-- et déclencheurs cessaient tous de s'appliquer.
--
-- Ce n'était pas exploitable — ce sont des fonctions de déclencheur, ou des
-- API dont l'EXECUTE est révoqué à PUBLIC. Mais « pas exploitable aujourd'hui »
-- n'est pas une propriété du schéma, c'est une propriété de l'état actuel des
-- GRANT. Le jour où l'un d'eux s'élargit, l'escalade devient réelle sans que
-- rien dans le code n'ait changé.
--
-- `crypto` et `inventory` étaient déjà propres : leurs migrations font
-- `SET ROLE`. Celle-ci rattrape les trois autres, et la règle de doctrine
-- `definer-is-not-owned-by-a-superuser` empêche la rechute.
--
-- ⚠ POUR LES MIGRATIONS SUIVANTES : elles tournent comme `dev`, donc tout
-- objet qu'elles créent appartiendra de nouveau à un superutilisateur. Fais
-- `SET ROLE admin_owner;` en tête, comme crypto et inventory. Le linter le
-- signalera sinon — c'est d'ailleurs lui qui a trouvé ce trou.
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     (aucun — cette migration ne change que des propriétaires)
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin_owner') THEN
    CREATE ROLE admin_owner NOLOGIN;
  END IF;
END $$;

COMMENT ON ROLE admin_owner IS
'Propriétaire des schémas de cette base. NOLOGIN : personne ne s''y connecte,
il n''existe que pour porter les objets — et pour que les fonctions SECURITY
DEFINER s''exécutent avec SES droits plutôt qu''avec ceux d''un
superutilisateur.';

DO $$
DECLARE
  r record;
  owner constant text := 'admin_owner';
BEGIN
  -- Les schémas d'abord : sans USAGE, le propriétaire ne peut pas nommer ce
  -- qu'il possède.
  FOR r IN SELECT nspname FROM pg_namespace
            WHERE nspname NOT LIKE 'pg\_%'
              AND nspname NOT IN ('information_schema', 'public')
  LOOP
    EXECUTE format('ALTER SCHEMA %I OWNER TO %I', r.nspname, owner);
  END LOOP;

  -- Tables, vues et séquences. Les partitions suivent leur parent, mais les
  -- nommer explicitement ne coûte rien et couvre le cas où l'une aurait été
  -- détachée.
  FOR r IN SELECT n.nspname, c.relname, c.relkind
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname NOT LIKE 'pg\_%'
              AND n.nspname NOT IN ('information_schema', 'public')
              AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
              -- Une séquence d'identité appartient à SA COLONNE : elle suit
              -- la table et refuse d'être transférée seule. La condition ne
              -- vise QUE les séquences : écrite plus large, elle écartait
              -- aussi les partitions et la table partitionnée elle-même —
              -- audit.event restait à dev, et la fonction DEFINER qui y écrit
              -- perdait le droit de le faire.
              AND NOT (c.relkind = 'S' AND EXISTS (
                SELECT FROM pg_depend d
                 WHERE d.objid = c.oid
                   AND d.classid = 'pg_class'::regclass
                   AND d.deptype IN ('a', 'i')))
  LOOP
    EXECUTE format('ALTER %s %I.%I OWNER TO %I',
      CASE r.relkind WHEN 'v' THEN 'VIEW'
                     WHEN 'm' THEN 'MATERIALIZED VIEW'
                     WHEN 'S' THEN 'SEQUENCE'
                     ELSE 'TABLE' END,
      r.nspname, r.relname, owner);
  END LOOP;

  -- Les fonctions : c'est pour elles que tout ceci existe.
  FOR r IN SELECT p.oid::regprocedure AS sig
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname NOT LIKE 'pg\_%'
              AND n.nspname NOT IN ('information_schema', 'public')
              -- Les fonctions d'une EXTENSION ne nous appartiennent pas.
              AND NOT EXISTS (SELECT FROM pg_depend d
                               WHERE d.objid = p.oid
                                 AND d.classid = 'pg_proc'::regclass
                                 AND d.deptype = 'e')
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO %I', r.sig, owner);
  END LOOP;

  -- Domaines et énumérations : un type possédé par un superutilisateur ne
  -- prête rien, mais le laisser derrière rendrait le transfert incomplet et
  -- la prochaine lecture du catalogue ambiguë.
  FOR r IN SELECT t.oid::regtype AS name, t.typtype
             FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname NOT LIKE 'pg\_%'
              AND n.nspname NOT IN ('information_schema', 'public')
              AND t.typtype IN ('d', 'e')
              AND NOT EXISTS (SELECT FROM pg_depend d
                               WHERE d.objid = t.oid
                                 AND d.classid = 'pg_type'::regclass
                                 AND d.deptype = 'e')
  LOOP
    EXECUTE format('ALTER %s %s OWNER TO %I',
      CASE r.typtype WHEN 'd' THEN 'DOMAIN' ELSE 'TYPE' END, r.name, owner);
  END LOOP;
END $$;

-- Down Migration

DO $$
DECLARE
  r record;
BEGIN
  FOR r IN SELECT p.oid::regprocedure AS sig
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname NOT LIKE 'pg\_%'
              AND n.nspname NOT IN ('information_schema', 'public')
              AND NOT EXISTS (SELECT FROM pg_depend d
                               WHERE d.objid = p.oid
                                 AND d.classid = 'pg_proc'::regclass
                                 AND d.deptype = 'e')
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO %I', r.sig, session_user);
  END LOOP;

  FOR r IN SELECT t.oid::regtype AS name, t.typtype
             FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname NOT LIKE 'pg\_%'
              AND n.nspname NOT IN ('information_schema', 'public')
              AND t.typtype IN ('d', 'e')
              AND NOT EXISTS (SELECT FROM pg_depend d
                               WHERE d.objid = t.oid
                                 AND d.classid = 'pg_type'::regclass
                                 AND d.deptype = 'e')
  LOOP
    EXECUTE format('ALTER %s %s OWNER TO %I',
      CASE r.typtype WHEN 'd' THEN 'DOMAIN' ELSE 'TYPE' END, r.name, session_user);
  END LOOP;

  FOR r IN SELECT n.nspname, c.relname, c.relkind
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname NOT LIKE 'pg\_%'
              AND n.nspname NOT IN ('information_schema', 'public')
              AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
              -- Une séquence d'identité appartient à SA COLONNE : elle suit
              -- la table et refuse d'être transférée seule. La condition ne
              -- vise QUE les séquences : écrite plus large, elle écartait
              -- aussi les partitions et la table partitionnée elle-même —
              -- audit.event restait à dev, et la fonction DEFINER qui y écrit
              -- perdait le droit de le faire.
              AND NOT (c.relkind = 'S' AND EXISTS (
                SELECT FROM pg_depend d
                 WHERE d.objid = c.oid
                   AND d.classid = 'pg_class'::regclass
                   AND d.deptype IN ('a', 'i')))
  LOOP
    EXECUTE format('ALTER %s %I.%I OWNER TO %I',
      CASE r.relkind WHEN 'v' THEN 'VIEW'
                     WHEN 'm' THEN 'MATERIALIZED VIEW'
                     WHEN 'S' THEN 'SEQUENCE'
                     ELSE 'TABLE' END,
      r.nspname, r.relname, session_user);
  END LOOP;

  FOR r IN SELECT nspname FROM pg_namespace
            WHERE nspname NOT LIKE 'pg\_%'
              AND nspname NOT IN ('information_schema', 'public')
  LOOP
    EXECUTE format('ALTER SCHEMA %I OWNER TO %I', r.nspname, session_user);
  END LOOP;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin_owner') THEN
    BEGIN
      DROP ROLE admin_owner;
    EXCEPTION WHEN dependent_objects_still_exist
                OR dependent_privilege_descriptors_still_exist THEN
      RAISE NOTICE 'role admin_owner kept: still referenced in this cluster';
    END;
  END IF;
END $$;
