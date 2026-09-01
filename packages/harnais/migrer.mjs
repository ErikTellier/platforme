// @ts-check
/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  MIGRE TOUTES LES BASES, UNE PAR SERVICE.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  UN DOSSIER DANS migrations/ = UNE BASE. C'est la seule liste de services du
 *  depot, la meme que lit `migrations/amorcer.sh`. Ajouter un service, c'est
 *  creer son dossier ; rien d'autre a declarer.
 *
 *  POURQUOI CE FICHIER VIT DANS packages/harnais
 *
 *  Parce que c'est le seul endroit du depot ou un `.mjs` est linte, verifie
 *  par tsc et testable. Pose a la racine, il echapperait a tout — et
 *  `verifier-paquets` ne le rattraperait pas non plus, puisqu'il ne regarde
 *  que les paquets declares.
 *
 *  Le nom du paquet est plus etroit que son contenu : « harnais » couvre mal
 *  un lanceur de migrations. A renommer le jour ou un troisieme outil s'y
 *  ajoute.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

/**
 * La racine du depot, trouvee en REMONTANT jusqu'au marqueur.
 *
 * Et non en comptant des `..` : la profondeur du paquet se trompe en silence
 * le jour ou il demenage. C'est deja arrive une fois ici.
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
const FICHIER_ENV = join(RACINE, '.env');

// LE .env SE CHARGE ICI AUSSI, et pas seulement dans l'enfant.
//
// `--envPath` ne renseigne que le processus node-pg-migrate. Ce fichier, lui,
// compose l'URL de chaque base : il lui faut les memes variables. Sans cette
// ligne il echoue sur POSTGRES_USER alors que le .env est juste a cote.
//
// `loadEnvFile` est natif depuis Node 21.7 — aucune dependance a ajouter pour
// lire un fichier de six lignes.
if (existsSync(FICHIER_ENV)) process.loadEnvFile(FICHIER_ENV);

/**
 * Les services, deduits des dossiers.
 *
 * Ceux a underscore n'en sont pas : `_amorcage` porte les scripts joues par
 * `amorcer.sh` avant toute migration.
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
 * Une variable d'environnement obligatoire, ou un refus qui la nomme.
 *
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
 * @param {string} service
 * @returns {string}
 */
function urlDe(service) {
  const utilisateur = encodeURIComponent(requise('POSTGRES_USER'));
  const secret = encodeURIComponent(requise('POSTGRES_PASSWORD'));
  const hote = process.env['POSTGRES_HOST'] ?? 'localhost';
  const port = process.env['POSTGRES_PORT'] ?? '5432';

  return `postgres://${utilisateur}:${secret}@${hote}:${port}/${service}`;
}

const action = process.argv[2] ?? 'up';
const liste = services();

if (liste.length === 0) {
  process.stderr.write(
    '\nAucun service : migrations/ ne contient aucun dossier.\n\n',
  );
  process.exit(1);
}

/** @type {string[]} */
const echecs = [];

for (const service of liste) {
  process.stdout.write(`\n══ ${service} ══\n`);

  const resultat = spawnSync(
    process.execPath,
    [
      join(
        RACINE,
        'node_modules',
        'node-pg-migrate',
        'bin',
        'node-pg-migrate.js',
      ),
      '--envPath',
      join(RACINE, '.env'),
      '-m',
      join(MIGRATIONS, service),
      action,
      ...process.argv.slice(3),
    ],
    {
      stdio: 'inherit',
      cwd: RACINE,
      env: { ...process.env, DATABASE_URL: urlDe(service) },
    },
  );

  if (resultat.status !== 0) echecs.push(service);
}

if (echecs.length > 0) {
  process.stderr.write(
    `\nREFUS : la migration a echoue pour ${echecs.join(', ')}.\n\n` +
      `  Les autres services ont pu aboutir : chaque base est migree\n` +
      `  separement, il n'y a pas de transaction commune entre elles.\n\n` +
      `  Le chemin des fichiers se lit ci-dessus, par service.\n\n`,
  );
  process.exit(1);
}

process.stdout.write(
  `\n${String(liste.length)} base(s) a jour : ${liste.join(', ')}\n\n`,
);
