-- LA DOCTRINE, VÉRIFIÉE SUR UNE BASE VIVANTE.
--
-- ═══ CE QUE CES ASSERTIONS APPORTENT QUE LES MIGRATIONS N'APPORTENT PAS ═══
--
-- Une migration décrit ce qu'elle POSE. Elle ne dit rien de ce que la suivante
-- a défait sans le vouloir. Ici il n'y a que des SELECT sur le catalogue :
-- aucune écriture, aucun objet créé, rien à nettoyer. Le fichier se joue donc
-- contre N'IMPORTE QUELLE base migrée — y compris celle qui sert — et rend un
-- verdict sur ELLE.
--
-- C'est la différence entre « le schéma que produisent nos migrations respecte
-- la doctrine » et « le schéma qui sert en ce moment la respecte ».
--
-- ═══ POURQUOI CE FICHIER EXISTE ═══
--
-- Trois vues avaient perdu `security_invoker` en silence. Elles avaient été
-- créées `WITH (security_invoker = TRUE)`, puis remplacées plus tard par un
-- `CREATE OR REPLACE VIEW ... AS` sans clause `WITH` — qui RÉINITIALISE les
-- options au lieu de les conserver.
--
-- Conséquence mesurée, plan à l'appui : la vue s'exécutait avec les droits de
-- son propriétaire, à qui la politique `owner_is_the_vetted_path` rend `true`
-- sans condition. `Seq Scan` SANS filtre — toutes les lignes de tous les
-- clients. Le cloisonnement, annulé par une clause oubliée.
--
-- Rien dans les migrations ne pouvait l'attraper : chacune était correcte
-- isolément. Seul le catalogue, relu après coup, le dit.
--
-- ═══ LANCER ═══
--
--   pnpm test:db
--
-- L'extension vit dans son propre schéma, pas dans `public` : ses mille
-- quatre-vingt-cinq fonctions se mêleraient sinon aux assertions ci-dessous,
-- qui comptent les fonctions du projet.

SET search_path TO pgtap, public;

SELECT plan(10);

-- ─────────────────────────────────────────────────────────────────────────
-- LA CLAUSE OUBLIÉE. Toute vue qui lit une table sous RLS s'exécute avec les
-- droits de SON APPELANT, jamais de son propriétaire.
--
-- `owner_is_the_vetted_path` accorde `USING (true)` à `<base>_owner` sur toutes
-- les tables protégées. C'est délibéré et nécessaire : sans elle, les fonctions
-- `SECURITY DEFINER` deviennent aveugles et plus personne ne se connecte.
--
-- Mais une VUE possédée par ce même rôle hérite du laissez-passer sans être une
-- fonction vérifiée. Elle tombe sous la politique du propriétaire au lieu de
-- celle écrite pour l'appelant — `tenant_visible`, `own_or_platform` — et rend
-- toutes les lignes, tous clients confondus.
--
-- ON NE TESTE PAS TOUTES LES VUES DE `api`. Beaucoup ne lisent aucune table
-- protégée : leur imposer `security_invoker` exprimerait une opinion, pas la
-- doctrine. Seules comptent celles qui touchent du RLS.
--
-- ON NE TESTE PAS NON PLUS SI LA VUE EST ACCORDÉE. Une vue non accordée
-- aujourd'hui le sera demain, et le `GRANT` qui l'ouvrira ne dira rien de ce
-- qu'il ouvre.
--
-- Cette assertion est née d'un incident : trois vues avaient perdu l'option en
-- silence. Elle en a immédiatement trouvé huit autres qui ne l'avaient jamais
-- eue.
-- LA RECHERCHE EST RECURSIVE, ET CE N'EST PAS UN RAFFINEMENT.
--
-- Une vue qui lit une vue qui lit une table protegee contourne tout autant :
-- chaque maillon sans `security_invoker` s'execute comme son proprietaire, et
-- le suivant ne voit donc jamais l'appelant d'origine.
--
-- Une premiere version ne regardait qu'un saut. Elle trouvait quatorze vues ;
-- la version recursive en trouve vingt-six. Les douze manquantes auraient
-- survecu a la correction, et le banc serait passe au vert en les couvrant.
SELECT is(
    (WITH RECURSIVE lit AS (
        SELECT v.oid AS vue, s.oid AS source, s.relkind AS genre
          FROM pg_depend d
          JOIN pg_rewrite r ON r.oid = d.objid
          JOIN pg_class v ON v.oid = r.ev_class
          JOIN pg_class s ON s.oid = d.refobjid
         WHERE v.relkind = 'v' AND s.relkind IN ('r', 'v') AND s.oid <> v.oid
        UNION
        SELECT l.vue, d.refobjid, s.relkind
          FROM lit l
          JOIN pg_rewrite r ON r.ev_class = l.source
          JOIN pg_depend d ON d.objid = r.oid
          JOIN pg_class s ON s.oid = d.refobjid
         WHERE l.genre = 'v' AND s.relkind IN ('r', 'v') AND s.oid <> l.source
      )
      SELECT coalesce(string_agg(DISTINCT n.nspname || '.' || v.relname, ', '), 'aucune')
        FROM lit l
        JOIN pg_class v ON v.oid = l.vue
        JOIN pg_namespace n ON n.oid = v.relnamespace
        JOIN pg_class t ON t.oid = l.source
       WHERE t.relkind = 'r'
         AND t.relrowsecurity
         AND coalesce(array_to_string(v.reloptions, ','), '') NOT LIKE '%security_invoker=true%'),
    'aucune',
    'every view reaching an RLS table runs as its caller, never as its owner'
);

-- ─────────────────────────────────────────────────────────────────────────
-- « Le schéma api ne contient que des vues. » Le service lit par là, jamais
-- les tables : c'est ce qui permet de changer une table sans changer le
-- contrat, et de n'exposer que ce qu'on a décidé d'exposer.
SELECT is(
    (SELECT count(*)::int
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'api' AND c.relkind IN ('r', 'p')),
    0,
    'the api schema holds views only, never a table'
);

-- ─────────────────────────────────────────────────────────────────────────
-- « SET ROLE <base>_owner en tête, toujours. » Un objet oublié appartiendrait
-- au compte de connexion — superutilisateur en développement, compte éphémère
-- d'OpenBao en production — et un SECURITY DEFINER prêterait ce statut à
-- quiconque peut l'appeler.
SELECT is(
    (SELECT count(DISTINCT c.relowner)::int
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ('admin', 'audit', 'api')
        AND c.relkind IN ('r', 'p', 'v', 'm', 'S')),
    1,
    'every object in the service schemas shares one owner'
);

-- Et cet unique propriétaire n'est PAS celui qui se connecte. C'est la moitié
-- de l'invariant qui manquerait si l'on ne comptait que les propriétaires
-- distincts : une base entièrement possédée par le superutilisateur en aurait
-- un seul, elle aussi.
SELECT is(
    (SELECT count(*)::int
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ('admin', 'audit', 'api')
        AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
        AND c.relowner = current_user::regrole),
    0,
    'no object is owned by the role that connects'
);

-- ─────────────────────────────────────────────────────────────────────────
-- Aucune fonction exécutable par PUBLIC. DEUX FAÇONS DE L'ÊTRE, et n'en tester
-- qu'une est l'erreur qui laisse passer : l'ACL absent — le défaut de
-- Postgres, pour la fonction que personne n'a touchée — et l'entrée explicite.
-- Les fonctions d'extension sont hors sujet : pgTAP accorde EXECUTE à PUBLIC
-- par conception.
SELECT is(
    (SELECT count(*)::int
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname NOT LIKE 'pg\_%'
        AND n.nspname NOT IN ('information_schema', 'public', 'pgtap')
        AND (p.proacl IS NULL
             OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a
                         WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'))
        AND NOT EXISTS (SELECT 1 FROM pg_depend d
                         WHERE d.objid = p.oid
                           AND d.classid = 'pg_proc'::regclass
                           AND d.deptype = 'e')),
    0,
    'no function of ours is executable by PUBLIC'
);

-- ─────────────────────────────────────────────────────────────────────────
-- Toute fonction SECURITY DEFINER fixe son `search_path`. Sans lui, l'appelant
-- choisit où la fonction va chercher ses tables : il lui suffit de poser un
-- schéma devant pour lui faire lire les siennes, avec les droits du
-- propriétaire.
SELECT is(
    (SELECT coalesce(string_agg(n.nspname || '.' || p.proname, ', ' ORDER BY 1), 'aucune')
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname IN ('admin', 'audit', 'api')
        AND p.prosecdef
        AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}')) cfg
                         WHERE cfg LIKE 'search\_path=%')),
    'aucune',
    'every SECURITY DEFINER function pins its search_path'
);

-- ─────────────────────────────────────────────────────────────────────────
-- « Nommer chaque contrainte. » Beaucoup partagent le SQLSTATE 23514 : sans
-- nom choisi, un test ne peut pas dire LAQUELLE a parlé. Postgres nomme
-- automatiquement en `_check` ; les contraintes de DOMAINE sont exclues
-- (`conrelid = 0`), leur nom n'étant jamais écrit à la main.
SELECT is(
    (SELECT count(*)::int
       FROM pg_constraint k JOIN pg_namespace n ON n.oid = k.connamespace
      WHERE n.nspname IN ('admin', 'audit')
        AND k.contype = 'c' AND k.conrelid <> 0 AND k.conname ~ '_check$'),
    0,
    'every table check constraint carries a chosen name'
);

-- ─────────────────────────────────────────────────────────────────────────
-- « Des faits et des décisions, jamais des états. » Un état se dérive de
-- `now()` par une vue. Une colonne calculable finit par mentir : deux sources
-- pour une même vérité en donnent une fausse.
--
-- `state` est délibérément absent de la liste : `admin.login_flow.state` est le
-- paramètre anti-CSRF d'OIDC, une valeur aléatoire et non un statut.
SELECT is(
    (SELECT coalesce(string_agg(table_schema || '.' || table_name || '.' || column_name,
                                ', ' ORDER BY 1), 'aucune')
       FROM information_schema.columns
      WHERE table_schema IN ('admin', 'audit')
        AND (column_name ~ '^is_'
             OR column_name IN ('status', 'active', 'expired', 'enabled', 'disabled'))),
    'aucune',
    'no column stores a state that a view could derive'
);

-- ─────────────────────────────────────────────────────────────────────────
-- AUCUN INDEX INVALIDE. Un index `indisvalid = false` figure au catalogue et
-- ne sert à rien : le planificateur l'ignore. Il ressemble à un index dans un
-- `\d`, et la requête qu'il devait porter balaie la table.
--
-- DEUX FAÇONS D'EN ARRIVER LÀ, et aucune ne fait de bruit. Un
-- `CREATE INDEX CONCURRENTLY` interrompu laisse un index mort-né. Et sur une
-- table PARTITIONNÉE, un parent dont les partitions n'ont pas l'index attaché
-- reste invalide.
--
-- CETTE ASSERTION EST NÉE D'UN INCIDENT, comme la première. Les quatre index
-- d'`audit.event` — par acteur, par table, par client, par transaction — se
-- sont retrouvés réduits à des parents sans enfants : `pg_get_indexdef` rend
-- `CREATE INDEX ... ON ONLY ...` pour un index partitionné, et `mutation-sql`
-- rejouait cette définition telle quelle. Quatorze partitions, zéro index,
-- quatorze `Seq Scan` — et un journal d'audit muet le jour où l'on enquête.
--
-- Rien ne rougissait : le schéma se dégradait à chaque mesure. Le lanceur est
-- corrigé ; ceci est ce qui le prouvera encore dans un an.
--
-- `indisready` complète : ni prêt ni valide, l'index est abandonné.
SELECT is(
    (SELECT coalesce(string_agg(n.nspname || '.' || c.relname, ', ' ORDER BY 1), 'aucun')
       FROM pg_index x
       JOIN pg_class c ON c.oid = x.indexrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname NOT LIKE 'pg\_%'
        AND n.nspname NOT IN ('information_schema', 'public', 'pgtap')
        AND (NOT x.indisvalid OR NOT x.indisready)),
    'aucun',
    'no index is invalid or half-built'
);

-- ─────────────────────────────────────────────────────────────────────────
-- UNE VUE ACCORDÉE S'OUVRE. Sinon l'octroi est un mensonge : la vue figure
-- dans un `\dv`, elle a son `GRANT`, et chaque appel rend `42501`.
--
-- LES VUES D'`api` PORTENT `security_invoker`, donc elles s'exécutent avec les
-- droits de L'APPELANT — qui doit pouvoir lire toute la chaîne en dessous, pas
-- seulement la vue du dessus. Une seule relation fermée en chemin suffit.
--
-- CETTE ASSERTION EST NÉE D'UN CONSTAT, comme les deux autres de ce fichier :
-- dix-huit vues sur trente-quatre étaient dans ce cas. Un tiers de la surface
-- de lecture, jamais remarqué parce que personne ne s'était jamais connecté
-- comme le rôle applicatif — les bancs tournaient en superutilisateur, qui
-- contourne le RLS et possède tout.
--
-- ELLE NE NOMME AUCUN RÔLE : elle prend ceux qui ont l'octroi, quels qu'ils
-- soient. Un service qui déclarerait demain un second plan de lecture serait
-- couvert sans qu'on y pense — et c'est ce qu'on veut d'une doctrine.
--
-- La récursion compte, ici comme pour `security_invoker` : `api.signing_key`
-- lit `akeys.signing_key` qui lit `akeys.key`. Un seul saut n'aurait vu que le
-- maillon du milieu.
SELECT is(
    (WITH RECURSIVE lit AS (
        SELECT v.oid AS vue, s.oid AS source
          FROM pg_depend d
          JOIN pg_rewrite r ON r.oid = d.objid
          JOIN pg_class v ON v.oid = r.ev_class
          JOIN pg_class s ON s.oid = d.refobjid
         WHERE v.relkind = 'v' AND s.relkind IN ('r', 'p', 'v') AND s.oid <> v.oid
        UNION
        SELECT l.vue, d.refobjid
          FROM lit l
          JOIN pg_rewrite r ON r.ev_class = l.source
          JOIN pg_depend d ON d.objid = r.oid
          JOIN pg_class s ON s.oid = d.refobjid
         WHERE s.relkind IN ('r', 'p', 'v') AND s.oid <> l.source
      )
      SELECT coalesce(string_agg(DISTINCT beneficiaire || ' : api.' || vue, ', '), 'aucune')
        FROM (
          SELECT g.rolname AS beneficiaire, v.relname AS vue
            FROM lit l
            JOIN pg_class v ON v.oid = l.vue
            JOIN pg_namespace vn ON vn.oid = v.relnamespace
            JOIN pg_class s ON s.oid = l.source
            JOIN pg_namespace sn ON sn.oid = s.relnamespace
            CROSS JOIN LATERAL aclexplode(v.relacl) a
            JOIN pg_roles g ON g.oid = a.grantee
           WHERE vn.nspname = 'api'
             AND a.privilege_type = 'SELECT'
             AND NOT (has_schema_privilege(g.oid, sn.oid, 'USAGE')
                      AND has_table_privilege(g.oid, s.oid, 'SELECT'))
        ) manquantes),
    'aucune',
    'every granted api view can actually be read by whoever it was granted to'
);

SELECT * FROM finish();
