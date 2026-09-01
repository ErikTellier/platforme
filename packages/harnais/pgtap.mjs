// @ts-check
/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  LES ASSERTIONS DE CATALOGUE, JOUEES SUR CHAQUE BASE.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  Chaque `.sql` de tests/pgtap/ est joue contre TOUTES les bases : ce sont des
 *  invariants de doctrine, vrais pour tout service. Un fichier place dans
 *  tests/pgtap/<service>/ ne vise que la base de ce service.
 *
 *  CE QU'UN TEL BANC ATTRAPE ET QU'UN TEST DE MIGRATION NE PEUT PAS
 *
 *  Une migration est correcte isolement et fausse en chaine. Trois vues
 *  avaient perdu `security_invoker` parce qu'un `CREATE OR REPLACE VIEW`
 *  posterieur reinitialise les options — chaque migration prise seule etait
 *  juste. Seul le catalogue, relu apres coup, le dit.
 *
 *  AUCUNE ECRITURE : que des SELECT sur le catalogue. Le banc se joue donc
 *  contre n'importe quelle base migree, sans rien y laisser.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import pg from 'pg';

/**
 * La racine du depot, trouvee en REMONTANT jusqu'au marqueur.
 *
 * Et non en comptant des `..` : la profondeur du paquet se trompe en silence le
 * jour ou il demenage. C'est deja arrive une fois ici.
 *
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
const BANCS = join(RACINE, 'tests', 'pgtap');
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
 * Les services, deduits des dossiers de migrations/ — la meme liste que lisent
 * `amorcer.sh` et `migrer.mjs`.
 *
 * @returns {string[]}
 */
function services() {
  if (!existsSync(MIGRATIONS)) return [];

  return readdirSync(MIGRATIONS, { withFileTypes: true })
    .filter((e) => e.isDirectory() && !e.name.startsWith('_'))
    .map((e) => e.name)
    .sort((a, b) => a.localeCompare(b));
}

/**
 * Les bancs a jouer contre un service : ceux de la racine, plus les siens.
 *
 * @param {string} service
 * @returns {string[]}
 */
function bancsDe(service) {
  if (!existsSync(BANCS)) return [];

  const communs = readdirSync(BANCS, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith('.sql'))
    .map((e) => join(BANCS, e.name));

  const propre = join(BANCS, service);
  const siens = existsSync(propre)
    ? readdirSync(propre)
        .filter((f) => f.endsWith('.sql'))
        .map((f) => join(propre, f))
    : [];

  return [...communs, ...siens].sort((a, b) => a.localeCompare(b));
}

/**
 * Le verdict d'un banc, lu dans sa sortie TAP.
 *
 * pgTAP ecrit une ligne par assertion : `ok 1 - ...` ou `not ok 1 - ...`. On ne
 * compte pas les `ok` — on cherche les `not ok`, et on VERIFIE que le nombre
 * d'assertions correspond au plan annonce. Sans ce second controle, un banc
 * interrompu au milieu passerait pour reussi.
 *
 * @param {string[]} lignes
 * @returns {{ echecs: string[]; jouees: number; prevues: number | null }}
 */
function verdict(lignes) {
  const echecs = lignes.filter((l) => l.startsWith('not ok'));
  const jouees = lignes.filter((l) => /^(ok|not ok)\b/.test(l)).length;

  const plan = lignes.find((l) => /^1\.\.\d+$/.test(l));
  const prevues = plan === undefined ? null : Number(plan.slice(3));

  return { echecs, jouees, prevues };
}

/**
 * Joue un banc dans une transaction annulee, et rend ses lignes TAP.
 *
 * ROLLBACK SYSTEMATIQUE : le banc ne doit rien laisser derriere lui, meme si un
 * fichier futur ecrivait par megarde. Aucune assertion actuelle n'ecrit, et
 * c'est precisement pour que ca reste vrai sans avoir a y penser.
 *
 * @param {import('pg').Client} client
 * @param {string} banc
 * @returns {Promise<string[]>}
 */
async function jouer(client, banc) {
  await client.query('BEGIN');

  try {
    /** @type {unknown} */
    const brut = await client.query(readFileSync(banc, 'utf8'));

    // `query` rend un resultat, ou UN TABLEAU quand la chaine porte plusieurs
    // instructions — ce qui est le cas d'un banc. Le type de `pg` ne modelise
    // pas cette seconde forme : on la nomme ici plutot que de propager un
    // `any` dans tout ce qui suit.
    const tous = /** @type {{ rows: Record<string, unknown>[] }[]} */ (
      Array.isArray(brut) ? brut : [brut]
    );

    return tous
      .flatMap((r) => r.rows)
      .map((ligne) => {
        // pgTAP n'emet que du texte. Tout le reste n'est pas une ligne TAP, et
        // le convertir donnerait « [object Object] » au lieu de le signaler.
        const valeur = Object.values(ligne)[0];
        return typeof valeur === 'string' ? valeur : '';
      })
      .flatMap((s) => s.split('\n'));
  } finally {
    await client.query('ROLLBACK');
  }
}

/**
 * Joue UN banc contre UNE base, l'affiche, et rend ses anomalies.
 *
 * Extrait en fonction pour tenir la limite d'imbrication : la boucle des bancs,
 * dans le `try` de la connexion, dans la boucle des services, y arrivait deja.
 *
 * @param {import('pg').Client} client
 * @param {string} service
 * @param {string} banc
 * @returns {Promise<string[]>}
 */
async function traiter(client, service, banc) {
  const nom = banc
    .slice(BANCS.length + 1)
    .split(/[\\/]/)
    .join('/');

  process.stdout.write(`\n══ ${service} · ${nom} ══\n`);

  const lignes = await jouer(client, banc);
  const { echecs, jouees, prevues } = verdict(lignes);

  for (const l of lignes) {
    if (l.trim() !== '') process.stdout.write(`  ${l}\n`);
  }

  const anomaliesDuBanc = echecs.map((e) => `${service} · ${nom} : ${e}`);

  // Le PLAN, et pas seulement les echecs. Un banc interrompu en cours de route
  // n'annonce aucun `not ok` : il se tait, et se tairait pour un succes.
  if (prevues !== null && jouees !== prevues) {
    anomaliesDuBanc.push(
      `${service} · ${nom} : ${String(jouees)} assertion(s) jouee(s) pour ${String(prevues)} annoncee(s)`,
    );
  }

  return anomaliesDuBanc;
}

// ═══ TROIS ARGUMENTS, ET SEUL LE PREMIER EST POUR UN HUMAIN ═══
//
//   pnpm test:db [service] [base] [banc]
//
// SERVICE  restreint a une base. Le mutant s'en sert : il joue la suite des
//          centaines de fois, et n'a aucune raison de la jouer sur les autres.
//
// BASE     A QUELLE BASE SE CONNECTER, quand ce n'est pas celle du service.
//          Le mutant travaille sur des CLONES — `admin_mutant_0`, `_1`… — pour
//          deux raisons : plusieurs ouvriers a la fois, et surtout ne jamais
//          amputer la base de developpement. Les bancs restent ceux du service ;
//          seule la connexion change.
//
// BANC     un seul fichier, par son nom. Sert le cache de tueurs : quand on sait
//          deja quel banc a tue une cible, on rejoue celui-la d'abord.
//
// Les deux derniers sont de la plomberie entre `mutation-sql.mjs` et ce
// fichier. Un humain n'ecrit que le premier.
const filtre = process.argv[2];
const baseVisee = process.argv[3];
const bancVise = process.argv[4];
const liste =
  filtre === undefined ? services() : services().filter((s) => s === filtre);

if (filtre !== undefined && liste.length === 0) {
  process.stderr.write(`
Aucun service nomme "${filtre}" dans migrations/.

`);
  process.exit(1);
}

if (liste.length === 0) {
  process.stderr.write(
    '\nAucun service : migrations/ ne contient aucun dossier.\n\n',
  );
  process.exit(1);
}

/** @type {string[]} */
const anomalies = [];

for (const service of liste) {
  const bancs =
    bancVise === undefined || bancVise === ''
      ? bancsDe(service)
      : bancsDe(service).filter((b) => b.split(/[\\/]/).pop() === bancVise);

  if (bancs.length === 0) {
    process.stdout.write(`\n══ ${service} ══\n  aucun banc\n`);
    continue;
  }

  const client = new pg.Client({
    host: process.env['POSTGRES_HOST'] ?? 'localhost',
    port: Number(process.env['POSTGRES_PORT'] ?? '5432'),
    user: requise('POSTGRES_USER'),
    password: requise('POSTGRES_PASSWORD'),
    database: baseVisee === undefined || baseVisee === '' ? service : baseVisee,
  });

  await client.connect();

  try {
    // L'extension vit dans SON schema : ses mille quatre-vingt-cinq fonctions
    // se meleraient sinon a celles que les assertions comptent.
    await client.query('CREATE SCHEMA IF NOT EXISTS pgtap');
    await client.query(
      'CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA pgtap',
    );

    for (const banc of bancs) {
      anomalies.push(...(await traiter(client, service, banc)));
    }
  } finally {
    await client.end();
  }
}

if (anomalies.length > 0) {
  process.stderr.write(
    [
      '',
      'REFUS : la doctrine n est pas respectee.',
      '',
      ...anomalies.map((a) => `  ${a}`),
      '',
      '',
    ].join('\n'),
  );
  process.exit(1);
}

process.stdout.write(
  `\n${String(liste.length)} base(s) conforme(s) a la doctrine\n\n`,
);
