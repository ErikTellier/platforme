// @ts-check
/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  LE SHELL QUI PORTE LE HARNAIS, RELU PAR UN OUTIL.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  Treize fichiers, cinq cents lignes, et ce sont EUX les gardes : les crochets
 *  et ce qu'ils appellent. Une erreur ici ne casse pas la construction, elle
 *  DESARME une verification — le crochet passe au vert en n'ayant rien
 *  verifie. C'est le seul endroit du depot ou une faute se traduit par une
 *  garde silencieuse plutot que par un refus.
 *
 *  Tout le reste est relu : le TypeScript par ESLint, le SQL par pgTAP et le
 *  mutant, les dependances par `audit` et `knip`. Le shell, non.
 *
 *  ═══ CE QU'IL TROUVE AUJOURD'HUI : RIEN ═══
 *
 *  Zero remarque au premier passage, et c'est dit franchement. Sa valeur n'est
 *  pas corrective, elle est PREVENTIVE : une variable non protegee, un `[` mal
 *  ferme, un `local` dans un `sh` qui n'en veut pas. Les fautes de shell ne se
 *  voient pas a la relecture — elles se voient le jour ou le chemin d'erreur
 *  s'execute, c'est-a-dire jamais, jusqu'a ce qu'il compte.
 *
 *  ═══ POURQUOI DOCKER, ET NON UN PAQUET npm ═══
 *
 *  Les paquets npm qui « fournissent » shellcheck telechargent un binaire a
 *  l'installation. `minimumReleaseAge`, `trustPolicy` et `allowBuilds` de ce
 *  depot existent precisement pour empecher ca. Docker est deja une dependance
 *  dure — la base y tourne — et l'image est officielle.
 *
 *  ABSENT, ON SAUTE. Meme choix que le banc pgTAP au pre-push : un outil qui
 *  fait echouer une poussee parce que Docker n'est pas demarre finit par se
 *  faire contourner, et un garde contourne ne garde rien.
 *
 *  ═══ LANCER ═══
 *
 *    pnpm lint:shell
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

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

// ═══════════════════════════════════════════════════════════════════════════
//  QUELS FICHIERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Les `.sh` d'un dossier, s'il existe.
 *
 * @param {string} dossier
 * @returns {string[]}
 */
function scriptsDe(dossier) {
  if (!existsSync(dossier)) return [];

  return readdirSync(dossier)
    .filter((f) => f.endsWith('.sh'))
    .map((f) => join(dossier, f));
}

/**
 * Tout ce qu'il y a a relire, en chemins absolus.
 *
 * LES CROCHETS N'ONT PAS D'EXTENSION : `.husky/pre-push` est un script, pas un
 * fichier de donnees. On les prend par leur dossier — un motif `*.sh` les
 * manquerait tous, et le banc passerait au vert en n'ayant lu que les gardes.
 *
 * `.husky/_` est ecarte : husky l'ecrit, ce n'est pas a nous de le relire.
 *
 * @returns {string[]}
 */
function fichiersShell() {
  const crochets = join(RACINE, '.husky');

  const aLaRacineDesCrochets = existsSync(crochets)
    ? readdirSync(crochets, { withFileTypes: true })
        .filter((e) => e.isFile())
        .map((e) => join(crochets, e.name))
    : [];

  return [
    ...aLaRacineDesCrochets,
    ...scriptsDe(join(crochets, 'garde')),
    ...scriptsDe(join(RACINE, 'migrations')),
    ...scriptsDe(join(RACINE, 'scripts')),
  ]
    .filter((f) => statSync(f).isFile())
    .sort((a, b) => a.localeCompare(b));
}

// ═══════════════════════════════════════════════════════════════════════════
//  OU EST DOCKER
//
//  ON NE L'APPELLE PAS PAR SON NOM. Un `spawn('docker')` laisse le systeme le
//  chercher dans `PATH` — et le premier dossier inscriptible de ce `PATH`
//  devient un endroit d'ou l'on execute du code arbitraire pendant un crochet
//  git, c'est-a-dire au moment le plus automatique de la journee.
//
//  `migrer.mjs` et `mutation-sql.mjs` echappent au probleme sans y penser :
//  ils lancent `process.execPath`, que Node connait en absolu. Docker n'a pas
//  d'equivalent, donc on le resout et on VERIFIE que le chemin est absolu.
//
//  `DOCKER=/chemin/absolu/docker` prend la main, pour une installation hors des
//  emplacements attendus.
// ═══════════════════════════════════════════════════════════════════════════

const EMPLACEMENTS = [
  'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe',
  '/usr/bin/docker',
  '/usr/local/bin/docker',
  '/opt/homebrew/bin/docker',
];

/** @returns {string | null} */
function cheminDocker() {
  const declare = process.env['DOCKER'];

  if (declare !== undefined && declare !== '') {
    return isAbsolute(declare) && existsSync(declare) ? declare : null;
  }

  return EMPLACEMENTS.find((c) => existsSync(c)) ?? null;
}

/**
 * @param {string} docker
 * @returns {boolean}
 */
function demonRepond(docker) {
  const r = spawnSync(docker, ['version', '--format', '{{.Server.Os}}'], {
    stdio: 'ignore',
    shell: false,
  });

  return r.status === 0;
}

// ═══════════════════════════════════════════════════════════════════════════
//  LA RELECTURE
// ═══════════════════════════════════════════════════════════════════════════

const fichiers = fichiersShell();

if (fichiers.length === 0) {
  process.stdout.write('\n  shell : aucun script a relire\n\n');
  process.exit(0);
}

const docker = cheminDocker();

if (docker === null || !demonRepond(docker)) {
  process.stderr.write('  shell : Docker injoignable, relecture sautee\n');
  process.exit(0);
}

// `-s sh` : ces scripts tournent sous le shell de git, pas sous bash. Laisser
// shellcheck deviner lui ferait accepter ce que `sh` refuse — `local`, `[[ ]]`,
// les tableaux — et le crochet echouerait a l'execution APRES avoir passe la
// relecture, ce qui est la pire des deux facons de se tromper.
//
// `-S warning` : les remarques de style ne sont pas des defauts, et une liste
// qu'on apprend a ignorer finit par cacher ce qui compte.
const relatifs = fichiers.map((f) => relative(RACINE, f).split('\\').join('/'));

const r = spawnSync(
  docker,
  [
    'run',
    '--rm',
    '-v',
    `${RACINE}:/depot`,
    '-w',
    '/depot',
    'koalaman/shellcheck-alpine:stable',
    'shellcheck',
    '-s',
    'sh',
    '-S',
    'warning',
    ...relatifs,
  ],
  { stdio: 'inherit', shell: false },
);

if (r.status !== 0) {
  process.stderr.write(
    [
      '',
      'REFUS : shellcheck a des remarques sur les scripts du harnais.',
      '',
      '  Ce sont les GARDES eux-memes. Une faute ici ne casse pas une',
      '  construction : elle desarme une verification, qui passe alors au vert',
      '  sans avoir rien verifie.',
      '',
      '  Relance :  pnpm lint:shell',
      '',
      '',
    ].join('\n'),
  );
  process.exit(1);
}

process.stdout.write(
  `\n  shell : ${String(fichiers.length)} script(s) sans remarque\n`,
);
