// @ts-check
/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  PROUVER QUE CHAQUE OBJET DU SCHEMA PORTE QUELQUE CHOSE.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  Des mutations choisies a la main sont circulaires : on casse ce pour quoi on
 *  vient d'ecrire un test, et le test l'attrape, evidemment. Ce script parcourt
 *  le schema ENTIER — il retire chaque objet a son tour, relance la suite, et
 *  exige qu'elle rougisse.
 *
 *  Le resultat n'est pas un score, c'est une LISTE — et elle est CLASSEE, parce
 *  qu'une liste de deux cent trente lignes indifferenciees s'apprend a ne plus
 *  lire, et qu'une liste qu'on ne lit plus ne mesure plus rien :
 *
 *    TUE       le retirer fait rougir la suite. L'objet porte quelque chose.
 *    IGNORE    d'autres objets en dependent : le retirer seul est impossible.
 *              On le signale, on ne force jamais un CASCADE — restaurer une
 *              cascade voudrait dire reconstruire les dependants, et un schema
 *              a moitie restaure empoisonne toutes les mutations suivantes.
 *    MUET      un index NON UNIQUE. Il sert le planificateur et ne refuse rien :
 *              aucune ecriture ne peut echouer a cause de lui, donc aucun banc
 *              de comportement ne peut le tuer. Ce n'est pas un trou, c'est une
 *              categorie que cet outil ne mesure pas.
 *    ECARTE    declare inatteignable dans `tests/pgtap/inatteignables.json`,
 *              AVEC SON MOTIF, affiche a chaque campagne. Le chemin qui le
 *              ferait parler n'existe pas — une garde masquee par une autre qui
 *              mord avant, une redondance deliberee, une course qu'un banc ne
 *              sait pas fabriquer.
 *    SURVIT    tout le reste, et c'est la LISTE DE TRAVAIL. Groupee par table,
 *              parce que « quinze sur operator_residency » se lit et que quinze
 *              lignes eparpillees dans deux cents ne se lisent pas.
 *
 *  ═══ CE QUI EMPECHE LES « ECARTES » DE POURRIR ═══
 *
 *  CHAQUE ENTREE EST FALSIFIABLE. Si un objet declare inatteignable se met a
 *  MOURIR, la campagne REFUSE et demande de retirer l'entree : quelqu'un a
 *  ecrit le banc qui l'atteint, le motif ne decrit plus rien, et le garder
 *  ferait disparaitre de la liste un objet desormais couvert.
 *
 *  Une derogation qui ne peut pas devenir fausse en silence n'est plus une
 *  derogation, c'est une explication verifiee a chaque passage.
 *
 *  ═══ CE QU'IL FAUT SAVOIR AVANT DE LIRE SON VERDICT ═══
 *
 *  UN MUTANT TUE NE VEUT DIRE QUELQUE CHOSE QUE SI LA SUITE EST VERTE QUAND
 *  L'OBJET EST LA. Le script refuse donc de tourner sur une suite deja rouge.
 *
 *  Et la suite doit eprouver le COMPORTEMENT, pas le catalogue. Retirer une
 *  contrainte ne change pas ce que `pg_constraint` dit des autres : les
 *  assertions de `doctrine.sql` n'en tuent aucune. Seuls les bancs qui ecrivent
 *  une ligne interdite et exigent un code d'erreur tuent quelque chose.
 *
 *  ═══ OU EN EST LA SUITE, MESURE LE 1er SEPTEMBRE 2026 ═══
 *
 *    admin   113 tues / 343 jouees / 153 ignores
 *            27 muets, 9 ecartes, 194 a ecrire
 *
 *      contrainte    28 / 130        declencheur   41 / 115
 *      index         11 /  47        politique     22 /  26
 *      fonction      11 /  25
 *
 *  Ce que chaque banc tue, et ce qu'il couvre :
 *
 *    cloisonnement.sql           16   les 13 politiques de securite de ligne
 *    session-et-cles.sql         16   admin.session, akeys.key
 *    rotation-des-jetons.sql      9   admin.token_pair, rotate_pair,
 *                                      validate_bearer
 *    journal.sql                  7   audit.event, et les premiers zz_audit
 *    flux-de-connexion.sql       10   admin.login_flow, open_ et consume_
 *    ticket-d-enrolement.sql     10   admin.enrollment_ticket et ses trois
 *                                      fonctions
 *    octroi-autorite.sql         11   admin.platform_admin, admin.admin_tenant
 *    commande-signee.sql          7   admin.signed_command
 *    demande-autorite.sql         7   admin.authority_request
 *    usurpation.sql               6   admin.impersonation
 *    clone-authentificateur.sql   5   webauthn.authenticator, disarm_clone
 *
 *  Plus `may_operate` et `signs_here`, que les bancs d'autorite tuent ensemble.
 *
 *  LES 194 SURVIVANTS NE SONT PAS FAIBLES — rien ne les eprouve. Le chiffre
 *  mesure ce qui reste a ecrire, et c'est a cela qu'il sert. En tete de ce qui
 *  manque : `admin.identity` (la federation), les deux tables de residence,
 *  `admin.spent_proof`, `admin.command_batch` au-dela de sa politique, et
 *  l'anneau de retention d'`audit`.
 *
 *  VINGT DES VINGT-TROIS `zz_audit` SURVIVENT ENCORE. `journal.sql` en tue
 *  trois — ceux des tables dont il relit la trace. Les autres tomberaient au
 *  fur et a mesure que chaque table gagne son banc ; ce n'est pas un trou a
 *  part, c'est le meme.
 *
 *  ═══ DEUX SORTES DE TUES, ET IL FAUT LES DISTINGUER ═══
 *
 *  Neuf `owner_is_the_vetted_path` meurent SANS QU AUCUNE ASSERTION NE LES
 *  NOMME. Les retirer aveugle les fonctions SECURITY DEFINER — qui s'executent
 *  comme `admin_owner`, et non comme le superutilisateur qui se connecte — et
 *  c'est le MONTAGE des bancs qui explose. Tue par dependance, pas par
 *  assertion : la politique porte quelque chose, mais aucune ligne ne dit quoi.
 *
 *  Les `tenant_visible` et `own_or_platform`, eux, sont tues par des assertions
 *  qui les nomment : `cloisonnement.sql` se connecte comme le role applicatif
 *  et compte ce qu'il voit. C'est la seule facon de les atteindre — un
 *  superutilisateur contourne le RLS, donc les cinq autres bancs ne les
 *  touchaient pas.
 *
 *  ═══ LANCER ═══
 *
 *    pnpm mutation:sql                    toutes les bases, toutes les familles
 *    pnpm mutation:sql admin              une base
 *    pnpm mutation:sql admin declencheur  une famille
 *
 *  Les familles : contrainte, index, declencheur, politique, fonction.
 *
 *    MUTATION_OUVRIERS=1  un seul ouvrier — sortie dans l'ordre, plus lente
 *    MUTATION_OUVRIERS=8  davantage, si la machine suit
 *
 *  ═══ POURQUOI C EST RAPIDE, ET OU PASSE LE TEMPS ═══
 *
 *  Une relance de suite coute 2,4 s, dont 0,2 s de demarrage de Node : le reste
 *  est le travail reel des bancs. Multiplie par trois cent quarante et une
 *  cibles, la campagne prenait dix-sept minutes.
 *
 *  LE LEVIER, repris de la version Go de ce banc :
 *
 *    N CLONES, N OUVRIERS   `CREATE DATABASE ... TEMPLATE` copie la base migree
 *                           en une seconde. Chaque ouvrier a la sienne, donc
 *                           quatre mutations avancent de front.
 *
 *  Mesure : dix-sept minutes ramenees a UNE MINUTE QUARANTE-CINQ, pour des
 *  verdicts identiques au mot pres — 45 tues, 153 ignores, 296 survivants.
 *
 *  Le second levier de la version Go, un cache de tueurs, a ete implemente,
 *  mesure et RETIRE : il ne paie pas ici. La raison est ecrite la ou il vivait,
 *  plus bas, pour que personne ne le reecrive.
 *
 *  CE QUI N EN EST PAS UN, et il vaut mieux le savoir : tourner dans un
 *  conteneur. La version Go y gagne beaucoup, parce qu'elle recompile — leur
 *  compose le dit, une minute quinze a froid contre vingt secondes avec les
 *  caches montes. Node ne compile pas : le demarrage pese 7 % ici, et le
 *  conteneur ne rendrait pas les 93 % restants.
 *
 *  HORS DU CHEMIN DE POUSSEE, et volontairement : c'est une mesure qu'on prend,
 *  pas un garde-fou qu'on franchit — `pnpm test:db`, lui, tourne au pre-push.
 *
 *  NE RIEN TOUCHER PENDANT QU IL TOURNE. Les bancs, surtout : le script relit
 *  les `.sql` a chaque mutation, et un fichier sauvegarde a mi-course rend la
 *  suite rouge pour une raison etrangere a l objet retire. La BASE, elle, ne
 *  risque plus rien — le travail se fait sur des clones jetables.
 */
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { cpus } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import pg from 'pg';

/**
 * @param {string} depuis
 * @returns {string}
 */
function racineDuDepot(depuis) {
  let courant = resolve(depuis);

  for (;;) {
    if (existsSync(join(courant, 'pnpm-workspace.yaml'))) return courant;

    const parent = dirname(courant);
    if (parent === courant) {
      throw new Error(`Racine du depot introuvable depuis ${depuis}.`);
    }
    courant = parent;
  }
}

const RACINE = racineDuDepot(import.meta.dirname);
const MIGRATIONS = join(RACINE, 'migrations');
const FICHIER_ENV = join(RACINE, '.env');

if (existsSync(FICHIER_ENV)) process.loadEnvFile(FICHIER_ENV);

/**
 * @param {string} nom
 * @returns {string}
 */
function requise(nom) {
  const valeur = process.env[nom];

  if (valeur === undefined || valeur === '') {
    throw new Error(`${nom} manquant — copier .env.example en .env`);
  }

  return valeur;
}

/**
 * LES SCHEMAS SE DEDUISENT, ILS NE SE LISTENT PAS.
 *
 * Une liste ecrite en dur a deja produit, chez l'auteur d'origine, un rapport
 * « 0 survivant inexplique » sur un schema qu'elle n'avait jamais regarde : le
 * troisieme schema n'y figurait pas. Un blanc-seing pour du code jamais lu.
 */
const SCHEMAS_APPLICATIFS = `(
  SELECT nspname FROM pg_namespace
   WHERE nspname NOT LIKE 'pg\\_%'
     AND nspname NOT IN ('information_schema', 'public', 'pgtap')
)`;

/**
 * Ce qu'on sait retirer, et comment le remettre.
 *
 * La definition vient du CATALOGUE, jamais des migrations : c'est l'objet tel
 * qu'il existe qu'on restaure, pas celui qu'on croit avoir ecrit.
 *
 * @type {Record<string, { lister: string; retirer: (o: Objet) => string; remettre: (o: Objet) => string }>}
 */
const FAMILLES = {
  contrainte: {
    lister: `
      SELECT c.conname AS nom,
             n.nspname || '.' || quote_ident(t.relname) AS porteur,
             pg_get_constraintdef(c.oid) AS definition
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
       WHERE n.nspname IN ${SCHEMAS_APPLICATIFS}
         AND c.contype <> 'p'
       ORDER BY 1`,
    retirer: (o) => `ALTER TABLE ${o.porteur} DROP CONSTRAINT ${quote(o.nom)}`,
    remettre: (o) =>
      `ALTER TABLE ${o.porteur} ADD CONSTRAINT ${quote(o.nom)} ${o.definition}`,
  },

  index: {
    // Les index qui servent une contrainte sont EXCLUS : ils appartiennent a la
    // contrainte, se retirent avec elle, et compteraient deux fois.
    //
    // ═══ `ON ONLY` EST RETIRE, ET CE N EST PAS UN DETAIL ═══
    //
    // Sur une table PARTITIONNEE, `pg_get_indexdef` rend :
    //
    //   CREATE INDEX event_by_actor ON ONLY audit.event (actor, ...)
    //
    // Rejouer cette definition telle quelle recree le PARENT SEUL. Sans index
    // sur les partitions, le parent reste `indisvalid = false` : le
    // planificateur l ignore, et la table redevient balayee de bout en bout.
    //
    // C EST ARRIVE ICI. Les quatre index d `audit.event` — par acteur, par
    // table, par client, par transaction — ont fini invalides apres un passage
    // du mutant. Quatorze partitions, zero index attache : la question « qui a
    // touche quoi, et quand » repondait par quatorze Seq Scan. Un journal
    // d audit sert justement le jour ou l on enquete.
    //
    // Rien ne rougissait : la suite passait, le rapport annonçait des index
    // « tues », et le schema se degradait a chaque mesure. C est l assertion de
    // catalogue de `doctrine.sql` — aucun index INVALID — qui ferme la porte
    // pour de bon ; ceci arrete de la pousser.
    lister: `
      SELECT c.relname AS nom,
             n.nspname || '.' || quote_ident(c.relname) AS porteur,
             replace(pg_get_indexdef(i.indexrelid), ' ON ONLY ', ' ON ') AS definition,
             -- UN INDEX NON UNIQUE NE REFUSE RIEN : il sert le planificateur.
             -- Aucune ecriture ne peut echouer a cause de lui, donc aucun banc
             -- de COMPORTEMENT ne peut le tuer. Ce n'est pas un trou de
             -- couverture, c'est une categorie d'objet que cet outil ne mesure
             -- pas — et le rapport le dit au lieu de le noyer.
             i.indisunique AS refuse
        FROM pg_index i
        JOIN pg_class c ON c.oid = i.indexrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname IN ${SCHEMAS_APPLICATIFS}
         AND NOT i.indisprimary
         AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = i.indexrelid)
       ORDER BY 1`,
    retirer: (o) => `DROP INDEX ${o.porteur}`,
    remettre: (o) => o.definition,
  },

  declencheur: {
    lister: `
      SELECT t.tgname AS nom,
             n.nspname || '.' || quote_ident(c.relname) AS porteur,
             pg_get_triggerdef(t.oid) AS definition
        FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname IN ${SCHEMAS_APPLICATIFS}
         AND NOT t.tgisinternal
       ORDER BY 1`,
    retirer: (o) => `DROP TRIGGER ${quote(o.nom)} ON ${o.porteur}`,
    remettre: (o) => o.definition,
  },

  politique: {
    lister: `
      SELECT p.polname AS nom,
             n.nspname || '.' || quote_ident(c.relname) AS porteur,
             'CREATE POLICY ' || quote_ident(p.polname)
               || ' ON ' || n.nspname || '.' || quote_ident(c.relname)
               || ' AS ' || CASE p.polpermissive WHEN true THEN 'PERMISSIVE' ELSE 'RESTRICTIVE' END
               || ' FOR ' || CASE p.polcmd
                    WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT'
                    WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' ELSE 'ALL' END
               || ' TO ' || coalesce(
                    (SELECT string_agg(quote_ident(r.rolname), ', ')
                       FROM pg_roles r WHERE r.oid = ANY(p.polroles)), 'PUBLIC')
               || coalesce(' USING (' || pg_get_expr(p.polqual, p.polrelid) || ')', '')
               || coalesce(' WITH CHECK (' || pg_get_expr(p.polwithcheck, p.polrelid) || ')', '')
               AS definition
        FROM pg_policy p
        JOIN pg_class c ON c.oid = p.polrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname IN ${SCHEMAS_APPLICATIFS}
       ORDER BY 1`,
    retirer: (o) => `DROP POLICY ${quote(o.nom)} ON ${o.porteur}`,
    remettre: (o) => o.definition,
  },

  fonction: {
    // ═══ CE QUE CETTE FAMILLE ATTRAPE, ET QU AUCUNE AUTRE NE VOIT ═══
    //
    // Une bonne part de la securite de ce schema tient dans du PL/pgSQL :
    // `disarm_clone` desarme un clone ET ferme sa session, `consume_pair`
    // depense un rafraichissement une seule fois. Un banc peut les eprouver a
    // fond sans qu aucune contrainte ni aucun declencheur ne meure — le
    // rapport lisait alors « rien de tue » pour du code entierement couvert.
    //
    // ═══ POURQUOI LA RESTAURATION EST PLUS LONGUE QU AILLEURS ═══
    //
    // `pg_get_functiondef` rend le corps, et RIEN D AUTRE. Rejouer cette seule
    // definition changerait deux choses en silence :
    //
    //   LE PROPRIETAIRE  La fonction reviendrait au compte qui se connecte —
    //                    superutilisateur ici. Un SECURITY DEFINER preterait
    //                    alors ce statut a quiconque peut l appeler.
    //   LES DROITS       Une fonction fraiche est EXECUTABLE PAR PUBLIC. C est
    //                    le defaut de Postgres, et c est exactement ce que
    //                    `a_default_acl_is_an_open_door` a ferme.
    //
    // On restaure donc le proprietaire, on referme PUBLIC, et on rejoue les
    // octrois lus dans `proacl`. La sixieme assertion de `doctrine.sql` — aucune
    // fonction executable par PUBLIC — surveille le resultat : si cette
    // restauration se trompe, la suite ne reverdit pas et le controle plus bas
    // arrete tout. C est ce qui rend cette famille sure a ajouter.
    //
    // ═══ BEAUCOUP SERONT « IGNORE », ET C EST LE SIGNE QUE CA MARCHE ═══
    //
    // Une fonction citee par un declencheur, une politique ou un index ne se
    // retire pas seule. Restent celles qu on appelle depuis un corps PL/pgSQL,
    // que Postgres ne suit pas — precisement les fonctions metier.
    lister: `
      SELECT p.proname AS nom,
             p.oid::regprocedure::text AS porteur,
             'SET ROLE ' || quote_ident(pg_get_userbyid(p.proowner)) || '; '
             || pg_get_functiondef(p.oid) || '; '
             || 'REVOKE ALL ON FUNCTION ' || p.oid::regprocedure || ' FROM PUBLIC; '
             || coalesce(
                  (SELECT string_agg('GRANT ' || a.privilege_type
                                     || ' ON FUNCTION ' || p.oid::regprocedure
                                     || ' TO ' || quote_ident(g.rolname) || '; ', '')
                     FROM aclexplode(p.proacl) a
                     JOIN pg_roles g ON g.oid = a.grantee
                    WHERE a.grantee <> 0), '')
             || 'RESET ROLE' AS definition
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname IN ${SCHEMAS_APPLICATIFS}
         AND p.prokind = 'f'
         AND NOT EXISTS (SELECT 1 FROM pg_depend d
                          WHERE d.objid = p.oid
                            AND d.classid = 'pg_proc'::regclass
                            AND d.deptype = 'e')
       ORDER BY 1`,
    retirer: (o) => `DROP FUNCTION ${o.porteur}`,
    remettre: (o) => o.definition,
  },
};

/**
 * @typedef {{ nom: string; porteur: string; definition: string;
 *             refuse?: boolean }} Objet
 */

/**
 * @param {string} nom
 * @returns {string}
 */
function quote(nom) {
  return `"${nom.split('"').join('""')}"`;
}

/** @returns {string[]} */
function services() {
  if (!existsSync(MIGRATIONS)) return [];

  return readdirSync(MIGRATIONS, { withFileTypes: true })
    .filter((e) => e.isDirectory() && !e.name.startsWith('_'))
    .map((e) => e.name)
    .sort((a, b) => a.localeCompare(b));
}

/**
 * @typedef {{ lister: string; retirer: (o: Objet) => string;
 *             remettre: (o: Objet) => string }} Recette
 */

/**
 * La recette d'une famille, ou un refus net.
 *
 * Un nom invente en ligne de commande doit se voir tout de suite, et non
 * produire zero cible — ce qui se lirait comme « rien a redire ».
 *
 * @param {string} famille
 * @returns {Recette}
 */
function recetteDe(famille) {
  const recette = FAMILLES[famille];

  if (recette === undefined) {
    throw new Error(
      `Famille inconnue : "${famille}". Attendu : ${Object.keys(FAMILLES).join(', ')}.`,
    );
  }

  return recette;
}

/**
 * Joue la suite et dit si elle passe — SANS BLOQUER LA BOUCLE.
 *
 * `spawnSync` bloquait tout : plusieurs ouvriers se seraient sagement mis en
 * file. C'est la seule raison de cette promesse.
 *
 * On capture la sortie d'erreur pour y lire QUEL banc a rougi. Elle ne coute
 * rien — le processus l'ecrit de toute facon — et c'est ce qui alimente le
 * cache de tueurs.
 *
 * @param {string} service
 * @param {string} base
 * @param {string} [banc]
 * @returns {Promise<{ verte: boolean; coupable: string | null }>}
 */
function jouerSuite(service, base, banc) {
  return new Promise((resoudre) => {
    const enfant = spawn(
      process.execPath,
      [join(import.meta.dirname, 'pgtap.mjs'), service, base, banc ?? ''],
      { cwd: RACINE, stdio: ['ignore', 'ignore', 'pipe'] },
    );

    let erreurs = '';
    enfant.stderr.on('data', (m) => (erreurs += String(m)));

    enfant.on('error', () => {
      resoudre({ verte: false, coupable: null });
    });

    enfant.on('close', (code) => {
      // `admin · admin/usurpation.sql : not ok 4 - …` — on ne garde que le nom
      // du fichier. Un banc qui EXPLOSE (erreur de montage) n'ecrit pas cette
      // ligne : on rend `null`, et la campagne suivante rejouera tout. Le cache
      // ne ment jamais, il rate parfois.
      const trouve = /· (?:.*[\\/])?([\w.-]+\.sql) :/.exec(erreurs);
      resoudre({ verte: code === 0, coupable: trouve?.[1] ?? null });
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  LES CLONES : LA SEULE FACON DE NE PAS ABIMER CE QU'ON MESURE
//
//  Le mutant travaillait sur la base de DEVELOPPEMENT. Deux consequences, et
//  les deux ont ete payees :
//
//    UNE MUTATION A LA FOIS.   La base est partagee, donc un seul ouvrier.
//    UN RATE EST DEFINITIF.    Une restauration imparfaite laisse la vraie base
//                              amputee. Les quatre index d'`audit.event` ont
//                              ainsi fini invalides — quatorze partitions, zero
//                              index attache — parce que `pg_get_indexdef` rend
//                              `ON ONLY` et qu'on rejouait cette definition.
//
//  `CREATE DATABASE ... TEMPLATE` copie la base migree en une seconde. Chaque
//  ouvrier a la sienne, et A LA FIN ON LES JETTE. Une restauration ratee ne
//  coute plus rien : elle part avec le clone. Le controle « la suite doit
//  reverdir » reste, parce qu'un rate fausse le VERDICT meme si le schema est
//  jetable.
//
//  CE QU'ON COPIE EST LEGITIME : la base telle que les migrations la
//  produisent, graine d'amorcage comprise. Pas une base pleine de donnees, dont
//  un banc tirerait des conclusions fausses.
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @param {string} base
 * @returns {import('pg').Client}
 */
function clientSur(base) {
  return new pg.Client({
    host: process.env['POSTGRES_HOST'] ?? 'localhost',
    port: Number(process.env['POSTGRES_PORT'] ?? '5432'),
    user: requise('POSTGRES_USER'),
    password: requise('POSTGRES_PASSWORD'),
    database: base,
  });
}

/**
 * @param {string[]} noms
 * @returns {Promise<void>}
 */
async function supprimerClones(noms) {
  if (noms.length === 0) return;

  const racine = clientSur('postgres');

  try {
    await racine.connect();
    for (const nom of noms) {
      await racine.query(`DROP DATABASE IF EXISTS ${quote(nom)} WITH (FORCE)`);
    }
  } catch (err) {
    // Un clone qui traine occupe de la place et rien d'autre. On le dit, on ne
    // s'arrete pas : la campagne, elle, a rendu son verdict.
    const aLaMain = noms.map((n) => `DROP DATABASE ${quote(n)};`).join(' ');
    process.stderr.write(
      `\n  clones NON SUPPRIMES (${String(err)})\n  a nettoyer :  ${aLaMain}\n`,
    );
  } finally {
    try {
      await racine.end();
    } catch {
      /* deja ferme */
    }
  }
}

/**
 * `CREATE DATABASE` ne se joue pas depuis la base qu'on copie : on passe par
 * `postgres`, et surtout on ne garde AUCUNE connexion sur la source — `WITH
 * TEMPLATE` la refuserait.
 *
 * @param {string} service
 * @param {number} combien
 * @returns {Promise<string[]>}
 */
async function clonerBases(service, combien) {
  const racine = clientSur('postgres');
  await racine.connect();

  /** @type {string[]} */
  const noms = [];

  try {
    for (let i = 0; i < combien; i += 1) {
      const nom = `${service}_mutant_${String(i)}`;
      await racine.query(`DROP DATABASE IF EXISTS ${quote(nom)} WITH (FORCE)`);
      await racine.query(
        `CREATE DATABASE ${quote(nom)} WITH TEMPLATE ${quote(service)}`,
      );
      noms.push(nom);
    }
  } catch (err) {
    // Le message brut de Postgres — « source database is being accessed by
    // other users » — est le bon, mais il ne dit pas quoi faire.
    process.stderr.write(
      [
        '',
        `REFUS : impossible de cloner "${service}".`,
        `  ${String(err)}`,
        '',
        '  `WITH TEMPLATE` exige qu AUCUNE session ne pende sur la source.',
        '  Fermer ce qui y est connecte — un psql ouvert, le service, un IDE —',
        '  puis relancer. Pour voir qui tient la base :',
        '',
        '    SELECT pid, application_name, state FROM pg_stat_activity',
        `     WHERE datname = '${service}';`,
        '',
        '',
      ].join('\n'),
    );
    await racine.end();
    await supprimerClones(noms);
    process.exit(1);
  }

  await racine.end();
  return noms;
}

/** @type {string[]} */
let clonesOuverts = [];

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    process.stderr.write('\n  interruption — on jette les clones\n');
    void supprimerClones(clonesOuverts).then(() => {
      process.exit(130);
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  LE CACHE DE TUEURS : ECRIT, MESURE, RETIRE
//
//  La version Go de ce banc garde, pour chaque cible tuee, QUEL test l'a tuee,
//  et rejoue celui-la d'abord a la campagne suivante. Chez elle le gain est
//  net. Ici il a ete implemente, mesure, et retire — le noter vaut mieux que de
//  laisser quelqu'un le reecrire.
//
//    famille declencheur, 23 tues sur 115 cibles
//      cache vide   43,7 s
//      cache chaud  45,4 s
//
//  LA RAISON TIENT A `pgtap.mjs` : il s'arrete au PREMIER banc qui explose. Or
//  une garde retiree fait generalement echouer le MONTAGE d'un banc, pas une
//  assertion — la suite rend donc la main en 0,6 s au lieu de 2,4 s. Sur un
//  tue, le chemin que le cache voulait raccourcir etait deja le chemin court.
//
//  Ce qui coute, c'est le SURVIVANT : lui fait tourner la suite jusqu'au bout,
//  et aucun cache n'y peut rien puisqu'il n'y a pas de tueur a se rappeler. Le
//  seul levier qui les touche est le parallelisme.
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
//  EPROUVER UNE CIBLE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @typedef {{ base: string; client: import('pg').Client }} Atelier
 * @typedef {{ retrait: string; retour: string; libelle: string; cle: string;
 *             refuse: boolean }} Cible
 * @typedef {'tue' | 'survit' | 'ignore'} Verdict
 */

/**
 * @param {Atelier} atelier
 * @param {string} service
 * @param {Cible} cible
 * @returns {Promise<Verdict>}
 */
async function eprouverCible(atelier, service, cible) {
  const { base, client } = atelier;
  const { retrait, retour, libelle } = cible;

  // ESSAI A BLANC. Un objet dont d'autres dependent ne se retire pas seul : on
  // le decouvre dans une transaction annulee, avant d'avoir rien casse.
  try {
    await client.query('BEGIN');
    await client.query(retrait);
    await client.query('ROLLBACK');
  } catch {
    await client.query('ROLLBACK');
    return 'ignore';
  }

  await client.query(retrait);
  const { verte } = await jouerSuite(service, base);
  await client.query(retour);

  if (verte) return 'survit';

  // UN TUE NE SE CROIT PAS SUR PAROLE.
  //
  // « La suite rougit sans l'objet » ne veut dire quelque chose que si elle
  // REVERDIT une fois l'objet remis. Sinon ce n'est pas l'objet qui portait
  // l'invariant : c'est la suite qui s'est cassee — restauration ratee, base
  // injoignable, banc modifie en cours de campagne — et tout ce qui suit se
  // lirait comme tue, puisque plus rien ne peut passer.
  //
  // C'EST ARRIVE. Une seule rupture, a la trente-sixieme mutation, a produit
  // deux cent quatre-vingt-un faux tues d'affilee : le rapport annoncait
  // 284/316 pour un schema dont trois tables etaient couvertes. Un compteur qui
  // ne peut que monter ne mesure rien.
  //
  // Le controle coute une execution de plus PAR TUE — jamais par survivant, qui
  // prouve deja que la suite tourne.
  const reprise = await jouerSuite(service, base);

  if (!reprise.verte) {
    process.stderr.write(
      [
        '',
        `REFUS : la suite ne reverdit pas apres avoir remis ${libelle}.`,
        '',
        '  Le verdict « tue » n est donc pas attribuable a cet objet, et',
        '  aucune des mutations suivantes ne serait interpretable.',
        '',
        `  Diagnostiquer :  pnpm test:db ${service} ${base}`,
        '  Puis verifier que l objet a bien ete remis :',
        `    ${retour}`,
        '',
        '  Si un banc a ete modifie pendant la campagne, c est la cause : le',
        '  lanceur relit les .sql a chaque mutation.',
        '',
        '',
      ].join('\n'),
    );
    await supprimerClones(clonesOuverts);
    process.exit(1);
  }

  return 'tue';
}

// ═══════════════════════════════════════════════════════════════════════════
//  LA CAMPAGNE
// ═══════════════════════════════════════════════════════════════════════════

const [filtreBase, filtreFamille] = process.argv.slice(2);
const bases = filtreBase === undefined ? services() : [filtreBase];
const familles =
  filtreFamille === undefined ? Object.keys(FAMILLES) : [filtreFamille];

// COMBIEN D'OUVRIERS. Quatre par defaut : au-dela, c'est Postgres qui devient
// le goulot, pas nous. `MUTATION_OUVRIERS=1` retrouve l'ancien comportement,
// utile quand on veut une sortie dans l'ordre.
const OUVRIERS = Math.max(
  1,
  Math.min(
    Number(process.env['MUTATION_OUVRIERS'] ?? '4'),
    Math.max(1, cpus().length - 1),
  ),
);

// ═══════════════════════════════════════════════════════════════════════════
//  LES OBJETS QU'AUCUN BANC NE PEUT ATTEINDRE
//
//  Un survivant est une QUESTION. Certains n'ont pourtant aucune reponse a
//  attendre : le chemin qui les ferait parler n'existe pas. Les laisser dans la
//  meme liste apprend a detourner le regard d'une liste — et une liste qu'on ne
//  lit plus ne mesure plus rien.
//
//  ON NE LES CACHE PAS, ON LES CLASSE, et le rapport dit combien.
//
//  CHAQUE ENTREE EST FALSIFIABLE. Si un objet declare inatteignable se met a
//  MOURIR, le lanceur refuse et demande de retirer l'entree. Une exception
//  devenue fausse ne peut donc pas survivre en silence a la campagne suivante —
//  c'est ce qui distingue ce fichier d'une liste de derogations.
// ═══════════════════════════════════════════════════════════════════════════

const CHEMIN_INATTEIGNABLES = join(
  RACINE,
  'tests',
  'pgtap',
  'inatteignables.json',
);

/** @returns {Map<string, string>} */
function lireInatteignables() {
  /** @type {Map<string, string>} */
  const declares = new Map();

  if (!existsSync(CHEMIN_INATTEIGNABLES)) return declares;

  const brut = /** @type {unknown} */ (
    JSON.parse(readFileSync(CHEMIN_INATTEIGNABLES, 'utf8'))
  );

  if (typeof brut !== 'object' || brut === null) return declares;

  for (const [cle, motif] of Object.entries(brut)) {
    // Les clefs qui commencent par `_` portent la prose du fichier.
    if (!cle.startsWith('_') && typeof motif === 'string') {
      declares.set(cle, motif);
    }
  }

  return declares;
}

const INATTEIGNABLES = lireInatteignables();

let tuesTotal = 0;
/** @type {string[]} */
const survivantsTotal = [];
/** @type {string[]} */
const ignoresTotal = [];
/** @type {string[]} */
const muetsTotal = [];
/** @type {string[]} */
const ecartesTotal = [];
/** @type {string[]} */
const perimeesTotal = [];

/**
 * Toutes les cibles des familles demandees, lues sur UN clone.
 *
 * Extraite de la campagne, qui sans elle empilait quatre niveaux de blocs. Le
 * schema d'un clone est celui de la source, et la source doit rester sans
 * connexion tant qu'on peut avoir a la recopier.
 *
 * @param {import('pg').Client} client
 * @returns {Promise<Cible[]>}
 */
async function listerCibles(client) {
  /** @type {Cible[]} */
  const cibles = [];

  for (const famille of familles) {
    const recette = recetteDe(famille);
    const { rows } = await client.query(recette.lister);

    cibles.push(
      .../** @type {Objet[]} */ (rows).map((objet) => ({
        retrait: recette.retirer(objet),
        retour: recette.remettre(objet),
        libelle: `${famille} ${objet.nom} sur ${objet.porteur}`,
        // La clef du fichier des inatteignables, et le porteur en fait partie :
        // deux schemas peuvent nommer leur contrainte pareil.
        cle: `${famille}|${objet.nom}|${objet.porteur}`,
        // `undefined` pour les familles qui ne se posent pas la question — un
        // declencheur refuse toujours quelque chose, par construction.
        refuse: objet.refuse ?? true,
      })),
    );
  }

  return cibles;
}

/**
 * @param {Atelier[]} ateliers
 * @returns {Promise<void>}
 */
async function fermerAteliers(ateliers) {
  for (const { client } of ateliers) {
    try {
      await client.end();
    } catch {
      /* deja ferme */
    }
  }
}

/**
 * Range un verdict et l'annonce. Extrait de la boucle des ouvriers, qui sans
 * lui depassait la profondeur d'imbrication permise.
 *
 * @param {Verdict} resultat
 * @param {Cible} cible
 * @returns {void}
 */
function enregistrer(resultat, cible) {
  const motif = INATTEIGNABLES.get(cible.cle);

  if (resultat === 'ignore') {
    ignoresTotal.push(cible.libelle);
    process.stdout.write(`  ignore  ${cible.libelle}\n`);
    return;
  }

  if (resultat === 'survit') {
    // TROIS SORTES DE SURVIVANTS, et les confondre est ce qui rend un rapport
    // illisible. Seule la troisieme est du travail a faire.
    if (motif !== undefined) {
      ecartesTotal.push(`${cible.libelle}\n            ${motif}`);
      process.stdout.write(`  ecarte  ${cible.libelle}\n`);
    } else if (!cible.refuse) {
      muetsTotal.push(cible.libelle);
      process.stdout.write(`  muet    ${cible.libelle}\n`);
    } else {
      survivantsTotal.push(cible.libelle);
      process.stdout.write(`  SURVIT  ${cible.libelle}\n`);
    }

    return;
  }

  // UNE EXCEPTION DEVENUE FAUSSE. L'objet est declare inatteignable et il vient
  // de MOURIR : quelqu'un a ecrit le banc qui l'atteint. Le motif ne decrit plus
  // rien, et le garder ferait disparaitre de la liste un objet desormais
  // couvert — donc mentir dans l'autre sens.
  if (motif !== undefined) perimeesTotal.push(cible.libelle);

  tuesTotal += 1;
  process.stdout.write(`  tue     ${cible.libelle}\n`);
}

for (const service of bases) {
  process.stdout.write(`\n══ ${service} ══\n`);

  // LE REFUS QUI SAUVE TOUT L'EXERCICE, et il se fait sur la VRAIE base : rien
  // ne sert de cloner un schema dont la suite est deja rouge.
  //
  // Sur une suite rouge, chaque mutation se lit comme tuee et le rapport
  // annonce « aucun survivant » pour un schema que rien n'eprouve. C'est pire
  // qu'un trou silencieux : c'est un certificat de bonne sante.
  const avant = await jouerSuite(service, service);

  if (!avant.verte) {
    process.stderr.write(
      `\nREFUS : la suite de "${service}" est rouge avant toute mutation.\n` +
        `  Chaque mutation se lirait comme tuee.\n` +
        `  Diagnostiquer :  pnpm test:db ${service}\n\n`,
    );
    process.exit(1);
  }

  const clones = await clonerBases(service, OUVRIERS);
  clonesOuverts = clones;

  /** @type {Atelier[]} */
  const ateliers = [];

  for (const nom of clones) {
    const client = clientSur(nom);
    await client.connect();
    ateliers.push({ base: nom, client });
  }

  try {
    // LA LISTE DES CIBLES vient d'un clone : le schema y est le meme, et la
    // source doit rester sans connexion tant qu'on peut avoir a recloner.
    const [premier] = ateliers;

    if (premier === undefined) {
      throw new Error(
        'Aucun atelier ouvert : impossible de lister les cibles.',
      );
    }

    const cibles = await listerCibles(premier.client);

    process.stdout.write(
      `  ${String(cibles.length)} cible(s), ${String(ateliers.length)} ouvrier(s)\n\n`,
    );

    // LA FILE PARTAGEE. JavaScript n'a qu'un fil : incrementer un compteur ne
    // demande aucun verrou, seulement de ne pas rendre la main entre la lecture
    // et l'ecriture — ce que ces deux lignes garantissent.
    let suivante = 0;

    await Promise.all(
      ateliers.map(async (atelier) => {
        for (;;) {
          const n = suivante;
          suivante += 1;

          const cible = cibles[n];
          if (cible === undefined) return;

          enregistrer(await eprouverCible(atelier, service, cible), cible);
        }
      }),
    );
  } finally {
    await fermerAteliers(ateliers);
    await supprimerClones(clones);
    clonesOuverts = [];
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  LE RAPPORT
//
//  IL SE LIT DE HAUT EN BAS, et la DERNIERE liste est la seule qui demande du
//  travail. Tout melanger donnait deux cent trente lignes dont on apprenait a
//  detourner le regard — et une liste qu'on ne lit plus ne mesure plus rien.
// ═══════════════════════════════════════════════════════════════════════════

// UNE EXCEPTION PERIMEE ARRETE TOUT, avant meme le rapport : le fichier des
// inatteignables decrirait alors un schema qui n'est plus celui-la.
if (perimeesTotal.length > 0) {
  process.stderr.write(
    [
      '',
      'REFUS : des objets declares inatteignables viennent d etre TUES.',
      '',
      '  Quelqu un a ecrit le banc qui les atteint — bonne nouvelle, et leur',
      '  entree ne decrit plus rien. La garder les retirerait d une liste ou',
      '  ils ont desormais leur place.',
      '',
      ...perimeesTotal.map((t) => `    ${t}`),
      '',
      `  A retirer de :  ${CHEMIN_INATTEIGNABLES}`,
      '',
      '',
    ].join('\n'),
  );
  process.exit(1);
}

process.stdout.write(
  `\n${String(tuesTotal)} tue(s) — les retirer fait rougir la suite\n` +
    `${String(ignoresTotal.length)} ignore(s) — d autres objets en dependent\n` +
    `${String(muetsTotal.length)} muet(s) — n opposent aucun refus, rien a tuer\n` +
    `${String(ecartesTotal.length)} ecarte(s) — inatteignables, motif ci-dessous\n` +
    `${String(survivantsTotal.length)} SURVIVANT(S) — la liste de travail\n`,
);

if (ecartesTotal.length > 0) {
  process.stdout.write('\n─── ecartes, et pourquoi ───\n\n');

  for (const e of ecartesTotal.toSorted((a, b) => a.localeCompare(b))) {
    process.stdout.write(`  ${e}\n\n`);
  }
}

if (muetsTotal.length > 0) {
  process.stdout.write(
    '\n─── muets : index non uniques, qui servent le planificateur ───\n\n',
  );

  for (const m of muetsTotal.toSorted((a, b) => a.localeCompare(b))) {
    process.stdout.write(`  ${m}\n`);
  }
}

// LES SURVIVANTS, GROUPES PAR TABLE. C'est la forme qui dit ou aller : « quinze
// sur operator_residency » se lit, quinze lignes eparpillees dans deux cents ne
// se lisent pas.
if (survivantsTotal.length > 0) {
  /** @type {Map<string, string[]>} */
  const parPorteur = new Map();

  for (const s of survivantsTotal) {
    const porteur = /sur (\S+)/.exec(s)?.[1] ?? '?';
    const deja = parPorteur.get(porteur);

    if (deja === undefined) parPorteur.set(porteur, [s]);
    else deja.push(s);
  }

  process.stdout.write('\n─── a ecrire, par table ───\n');

  const groupes = [...parPorteur.entries()].toSorted(
    (a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]),
  );

  for (const [porteur, objets] of groupes) {
    // Le porteur est deja le titre du groupe : le repeter sur chaque ligne
    // rendrait la colonne illisible.
    const suffixe = ` sur ${porteur}`;

    process.stdout.write(`\n  ${porteur} (${String(objets.length)})\n`);

    for (const o of objets.toSorted((a, b) => a.localeCompare(b))) {
      process.stdout.write(`    ${o.replace(suffixe, '')}\n`);
    }
  }

  process.stdout.write('\n');
}

// LE CODE DE SORTIE RESTE 0. Un survivant est une QUESTION, pas un echec : il
// dit qu'un invariant n'est teste par rien, ou qu'un objet est redondant. Faire
// rougir la chaine sur ce constat n'apprendrait rien a personne — c'est le
// rapport qu'on lit, pas le code de retour.
