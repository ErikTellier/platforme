-- Up Migration

-- UNE CLAUSE DE SÉCURITÉ QUE POSTGRES ACCEPTE ET N'ENREGISTRE PAS.
--
-- Chaque schéma initial porte cette ligne, avec ce commentaire :
--
--   « Le défaut de Postgres est d'accorder EXECUTE à PUBLIC sur toute
--     fonction créée : sans cette ligne, la prochaine migration rouvre le
--     trou sans que personne l'écrive. »
--
--   ALTER DEFAULT PRIVILEGES FOR ROLE admin_owner IN SCHEMA admin
--       REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
--
-- La ligne est là. Le trou s'est rouvert quand même — sur la première
-- fonction ajoutée après coup.
--
-- Postgres n'enregistre un privilège par défaut que s'il reste une
-- permission POSITIVE à écrire. Un REVOKE qui ne laisse rien produit un ACL
-- vide, Postgres le considère équivalent à « pas d'entrée », et
-- pg_default_acl reste vide — vérifié : zéro ligne dans les six bases,
-- alors que la clause y figure partout. La phrase est syntaxiquement
-- valide, sémantiquement muette. La forme GRANT, elle, s'enregistre.
--
-- C'est le pire genre de défaut : il se relit comme une protection. Aucune
-- revue de code ne l'aurait vu, parce qu'il n'y a rien à voir — il fallait
-- interroger le catalogue.
--
-- Ce qui suit fait donc deux choses :
--   1. le REVOKE explicite sur les fonctions déjà là ;
--   2. et pour l'avenir, rien ici — c'est le contrôle de doctrine
--      `every-function-decides-its-callers` qui tient le rôle, parce qu'un
--      contrôle qui interroge le catalogue ne peut pas devenir muet.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

DO $$
DECLARE
    f record;
    n int := 0;
BEGIN
    FOR f IN
        SELECT p.oid::regprocedure AS sig
          FROM pg_proc p
          JOIN pg_namespace ns ON ns.oid = p.pronamespace
         -- Tous nos schémas, pas une liste : cette migration a d'abord été
         -- écrite avec ('admin', 'audit') et a laissé sept fonctions ouvertes
         -- dans akeys, jwks, tenant et webauthn. Troisième fois qu'une liste
         -- de schémas codée en dur rate quelque chose ici.
         WHERE ns.nspname NOT LIKE 'pg\_%'
           AND ns.nspname NOT IN ('information_schema', 'public')
           -- Deux façons pour PUBLIC d'avoir EXECUTE : l'ACL absent (le
           -- défaut de Postgres) ou une entrée explicite. Ne tester que la
           -- première laissait la seconde intacte — et c'est exactement ce
           -- qu'a produit la rétrogradation de cette migration sur elle-même.
           AND (p.proacl IS NULL
                OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a
                            WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'))
           -- Les fonctions d'extension ne sont pas les nôtres : citext
           -- accorde EXECUTE à PUBLIC par conception, et le lui retirer
           -- casserait l'extension.
           AND NOT EXISTS (SELECT 1 FROM pg_depend d
                            WHERE d.objid = p.oid
                              AND d.classid = 'pg_proc'::regclass
                              AND d.deptype = 'e')
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f.sig);
        n := n + 1;
    END LOOP;
    RAISE NOTICE '% function(s) no longer executable by PUBLIC', n;
END;
$$;

-- Down Migration

DO $$
DECLARE f record;
BEGIN
    FOR f IN
        SELECT p.oid::regprocedure AS sig
          FROM pg_proc p
          JOIN pg_namespace ns ON ns.oid = p.pronamespace
         -- Tous nos schémas, pas une liste : cette migration a d'abord été
         -- écrite avec ('admin', 'audit') et a laissé sept fonctions ouvertes
         -- dans akeys, jwks, tenant et webauthn. Troisième fois qu'une liste
         -- de schémas codée en dur rate quelque chose ici.
         WHERE ns.nspname NOT LIKE 'pg\_%'
           AND ns.nspname NOT IN ('information_schema', 'public')
           AND NOT EXISTS (SELECT 1 FROM pg_depend d
                            WHERE d.objid = p.oid
                              AND d.classid = 'pg_proc'::regclass
                              AND d.deptype = 'e')
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO PUBLIC', f.sig);
    END LOOP;
END;
$$;
