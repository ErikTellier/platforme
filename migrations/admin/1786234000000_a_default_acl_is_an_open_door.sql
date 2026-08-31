-- Up Migration

-- Un ACL par défaut est une porte ouverte.
--
-- ═══ COMMENT CE TROU A ÉTÉ TROUVÉ ═══
--
-- En écrivant les assertions pgTAP, qui interrogent le catalogue d'une base
-- MIGRÉE plutôt qu'une base jetable. Trois fonctions y étaient exécutables par
-- PUBLIC :
--
--     admin.ticket_supersede         SECURITY DEFINER
--     admin.ticket_emission_guard    SECURITY DEFINER
--     webauthn.revocation_is_final
--
-- ═══ POURQUOI LE BALAYAGE NE LES AVAIT PAS PRISES ═══
--
-- `public_execute_is_closed` est un balayage PONCTUEL : il ferme ce qui existe
-- au moment où il tourne. Les deux `ticket_*` naissent onze migrations plus
-- tard, `revocation_is_final` vingt-quatre plus tard. Rien ne les a couvertes.
--
-- La suite par défaut aurait dû être `ALTER DEFAULT PRIVILEGES`, et cette
-- migration-là raconte précisément pourquoi elle ne suffit pas : Postgres
-- n'enregistre un privilège par défaut que s'il reste une permission positive à
-- écrire, donc un REVOKE seul produit un ACL vide et `pg_default_acl` reste
-- vide. « Le pire genre de défaut : il se relit comme une protection. »
--
-- ═══ POURQUOI LE CONTRÔLE DE DOCTRINE NE L'A PAS DIT NON PLUS ═══
--
-- C'est le vrai défaut, et il est plus grave que les trois fonctions.
--
-- `TestExecuteIsGrantedToNobodyByDefault` devait tenir ce rôle « parce qu'un
-- contrôle qui interroge le catalogue ne peut pas devenir muet ». Il testait
--
--     EXISTS (SELECT 1 FROM aclexplode(p.proacl) WHERE grantee = 0)
--
-- Or `aclexplode(NULL)` rend ZÉRO LIGNE. Et `proacl IS NULL` est justement le
-- cas de la fonction que personne n'a touchée : elle garde le défaut de
-- Postgres, qui est EXECUTE à PUBLIC. Le contrôle ne voyait que les ouvertures
-- ÉCRITES, jamais les ouvertures HÉRITÉES — c'est-à-dire toutes celles qui
-- arrivent sans que personne ne les décide.
--
-- Le balayage, lui, testait bien les deux. Le test corrigé teste les deux aussi.
--
-- ═══ CE QUE ÇA PERMETTAIT ═══
--
-- Peu, et il faut le dire : les trois rendent `trigger`. Postgres refuse
-- d'appeler directement une fonction déclencheur, donc le `SECURITY DEFINER`
-- des deux premières ne se prêtait à personne. L'exposition est théorique.
--
-- Ce n'est pas une raison de la laisser. L'invariant « aucune fonction n'est
-- exécutable par PUBLIC » était FAUX dans le schéma vivant, et le contrôle
-- chargé de le prouver ne pouvait pas s'en apercevoir. C'est cette deuxième
-- phrase qui compte.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code. Elle ne fait que retirer un privilège.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

DO $$
DECLARE
    f record;
    n int := 0;
BEGIN
    -- LA MÊME REQUÊTE QUE `public_execute_is_closed`, MOT POUR MOT, et c'est
    -- délibéré : deux formulations du même invariant divergent, et c'est
    -- toujours celle qu'on ne relit pas qui rate quelque chose.
    FOR f IN
        SELECT p.oid::regprocedure AS sig
          FROM pg_proc p
          JOIN pg_namespace ns ON ns.oid = p.pronamespace
         WHERE ns.nspname NOT LIKE 'pg\_%'
           AND ns.nspname NOT IN ('information_schema', 'public')
           AND (p.proacl IS NULL
                OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a
                            WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'))
           -- Les fonctions d'extension ne sont pas les nôtres. pgTAP en pose
           -- mille quatre-vingt-cinq dans son schéma, ouvertes par conception ;
           -- les lui retirer casserait l'extension qui sert à le vérifier.
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

-- ON NE ROUVRE PAS UNE PORTE. Rendre EXECUTE à PUBLIC serait rétablir un défaut,
-- pas annuler un changement. L'annulation est donc muette, comme celle de
-- `public_execute_is_closed`.
SELECT 1;
