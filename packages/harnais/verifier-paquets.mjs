// @ts-check
/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  TOUT PAQUET DOIT DECLARER SES VERROUS.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  LE TROU QUE CE FICHIER BOUCHE
 *
 *  `turbo run test` n'execute que les paquets qui DECLARENT un script `test`.
 *  Un paquet qui n'en declare pas n'echoue pas : il est ignore, en silence, et
 *  turbo annonce meme un succes. Mesure faite — un `apps/facturation` sans
 *  aucun script laissait turbo dire « 3 successful » alors que rien de ce
 *  paquet n'avait ete verifie.
 *
 *  Un verrou qu'on evite en ne le declarant pas n'est pas un verrou.
 *
 *  CE QUI EST EXIGE DEPEND DE CE QUE LE PAQUET CONTIENT
 *
 *  Un paquet qui n'expose que du JSON — `typescript-config` — n'a rien a
 *  linter ni a tester. Une exigence uniforme forcerait a ecrire des scripts
 *  vides, et un script vide est exactement le vert qui ne prouve rien.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

/**
 * La racine du depot, trouvee en REMONTANT jusqu'au marqueur.
 *
 * Et non `resolve(dirname, '..', '..')` : compter les niveaux encode la
 * profondeur du paquet, et se trompe en silence le jour ou il demenage — ce qui
 * vient precisement d'arriver a ce fichier, passe de outils/ a packages/.
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

const RACINE_PAR_DEFAUT = racineDuDepot(import.meta.dirname);

/** Le separateur de chemin de Windows, ecrit par son code pour rester lisible. */
const SEPARATEUR = String.fromCharCode(92);

/** Dossiers engendres : ils ne disent rien de ce que le paquet contient. */
const IGNORES = new Set([
  'node_modules',
  'dist',
  'coverage',
  '.stryker-tmp',
  'reports',
]);

/**
 * Lit un JSON en lui donnant une forme, plutot que de propager un `any`.
 *
 * @template T
 * @param {string} chemin
 * @returns {T}
 */
function lireJson(chemin) {
  // Passage par `unknown` : `JSON.parse` rend `any`, et rendre un `any`
  // directement propagerait le flou a tous les appelants. Le transtypage se
  // fait ici, une fois, et l'appelant declare la forme qu'il attend.
  /** @type {unknown} */
  const brut = JSON.parse(readFileSync(chemin, 'utf8'));

  return /** @type {T} */ (brut);
}

/**
 * Les motifs de `packages:` dans pnpm-workspace.yaml.
 *
 * Lus la-bas plutot que recopies ici : deux listes finiraient par diverger, et
 * un paquet absent de celle-ci echapperait au controle sans que rien ne le
 * signale — exactement le defaut que ce fichier existe pour empecher.
 *
 * @param {string} racine
 * @returns {string[]}
 */
function motifsDePaquets(racine) {
  const lignes = readFileSync(
    join(racine, 'pnpm-workspace.yaml'),
    'utf8',
  ).split('\n');
  /** @type {string[]} */
  const motifs = [];
  let dansLaSection = false;

  for (const ligne of lignes) {
    if (ligne.startsWith('packages:')) {
      dansLaSection = true;
      continue;
    }
    if (!dansLaSection) continue;

    // Une cle non indentee clot la section.
    if (/^\S/.test(ligne)) break;

    const trouve = /^\s+-\s*["']?([^"'\s]+)["']?/.exec(ligne);
    if (trouve?.[1] !== undefined) motifs.push(trouve[1]);
  }

  return motifs;
}

/**
 * Les dossiers de paquets du depot, deduits des motifs.
 *
 * @param {string} racine
 * @returns {string[]}
 */
function paquets(racine) {
  return motifsDePaquets(racine).flatMap((motif) => {
    if (!motif.endsWith('/*')) {
      const chemin = join(racine, motif);
      return existsSync(join(chemin, 'package.json')) ? [chemin] : [];
    }

    const base = join(racine, motif.slice(0, -2));
    if (!existsSync(base)) return [];

    return readdirSync(base, { withFileTypes: true })
      .filter((entree) => entree.isDirectory())
      .map((entree) => join(base, entree.name))
      .filter((chemin) => existsSync(join(chemin, 'package.json')));
  });
}

/**
 * Les fichiers du paquet, chemins normalises, sans les dossiers engendres.
 *
 * @param {string} paquet
 * @returns {string[]}
 */
function fichiersDe(paquet) {
  return readdirSync(paquet, { recursive: true, withFileTypes: true })
    .filter((entree) => entree.isFile())
    .map((entree) =>
      join(entree.parentPath, entree.name)
        .slice(paquet.length + 1)
        .split(SEPARATEUR)
        .join('/'),
    )
    .filter((chemin) => !chemin.split('/').some((part) => IGNORES.has(part)));
}

/**
 * Les scripts attendus qui manquent au manifeste.
 *
 * @param {Record<string, string>} scripts
 * @param {string[]} requis
 * @returns {string[]}
 */
function scriptsManquants(scripts, requis) {
  return requis
    .filter((nom) => scripts[nom] === undefined)
    .map((nom) => `script "${nom}" manquant`);
}

/**
 * Ce que le banc de couverture doit garantir.
 *
 * @param {string} paquet
 * @returns {string[]}
 */
function anomaliesDeCouverture(paquet) {
  const chemin = join(paquet, 'vitest.config.ts');
  if (!existsSync(chemin)) return ['vitest.config.ts manquant'];

  const contenu = readFileSync(chemin, 'utf8');
  /** @type {string[]} */
  const anomalies = [];

  if (!contenu.includes('thresholds')) {
    anomalies.push('vitest.config.ts ne fixe aucun seuil de couverture');
  }
  // Sans `perFile`, une moyenne flatteuse masque un fichier entierement nu.
  if (!contenu.includes('perFile')) {
    anomalies.push('seuils de couverture sans "perFile"');
  }
  // On cherche le REGLAGE, pas le mot : un commentaire qui explique son retrait
  // ne doit pas declencher le refus. Sans regex — les echappements s'y perdent
  // trop facilement, et un motif casse ne signalerait plus rien, en silence.
  if (contenu.split(' ').join('').includes('passWithNoTests:')) {
    anomalies.push('"passWithNoTests" rend le banc vert sans rien executer');
  }

  return anomalies;
}

/**
 * Ce que les tests de mutation doivent garantir.
 *
 * @param {string} paquet
 * @returns {string[]}
 */
function anomaliesDeMutation(paquet) {
  const chemin = join(paquet, 'stryker.config.json');
  if (!existsSync(chemin)) return ['stryker.config.json manquant'];

  /** @type {{ thresholds?: { break?: number } }} */
  const config = lireJson(chemin);

  return config.thresholds?.break == null
    ? ['stryker.config.json sans seuil bloquant ("thresholds.break")']
    : [];
}

/**
 * Ce qu'un paquet portant du code metier doit prouver.
 *
 * @param {string} paquet
 * @param {Record<string, string>} scripts
 * @returns {string[]}
 */
function anomaliesDeSources(paquet, scripts) {
  /** @type {string[]} */
  const anomalies = [
    ...scriptsManquants(scripts, ['build', 'test', 'mutation']),
  ];

  // Declarer `test` ne suffit pas : `echo ok` passerait. On exige la mesure.
  const test = scripts['test'];
  if (test !== undefined && !test.includes('--coverage')) {
    anomalies.push('le script "test" ne mesure pas la couverture (--coverage)');
  }

  return [
    ...anomalies,
    ...anomaliesDeCouverture(paquet),
    ...anomaliesDeMutation(paquet),
  ];
}

/**
 * Les anomalies du depot, sous forme de lignes pretes a afficher.
 *
 * RENDUE plutot qu'affichee : c'est ce qui la rend testable. Une fonction qui
 * ecrit sur stderr et appelle `process.exit` ne se verifie pas.
 *
 * @param {string} [racine]
 * @returns {string[]}
 */
export function verifierPaquets(racine = RACINE_PAR_DEFAUT) {
  return paquets(racine).flatMap((paquet) => {
    /** @type {{ scripts?: Record<string, string> }} */
    const manifeste = lireJson(join(paquet, 'package.json'));
    const scripts = manifeste.scripts ?? {};
    const fichiers = fichiersDe(paquet);

    const aDuCodeLintable = fichiers.some((f) =>
      ['.ts', '.js', '.mjs', '.cjs'].some((ext) => f.endsWith(ext)),
    );
    const aDesSources = fichiers.some(
      (f) =>
        f.startsWith('src/') && f.endsWith('.ts') && !f.endsWith('.spec.ts'),
    );

    const problemes = [
      ...(aDuCodeLintable
        ? scriptsManquants(scripts, ['lint', 'typecheck'])
        : []),
      ...(aDesSources ? anomaliesDeSources(paquet, scripts) : []),
    ];

    const nom = paquet
      .slice(racine.length + 1)
      .split(SEPARATEUR)
      .join('/');
    return problemes.map((probleme) => `  ${nom} : ${probleme}`);
  });
}

// ─── Usage en ligne de commande ──────────────────────────────────────────────
const anomaliesCli = verifierPaquets();

if (anomaliesCli.length > 0) {
  process.stderr.write(
    [
      '',
      'REFUS : un paquet ne declare pas tous ses verrous.',
      '',
      ...anomaliesCli,
      '',
      '  turbo IGNORE une tache non declaree, sans rien dire. Un paquet',
      '  incomplet traverserait donc le harnais sans etre verifie.',
      '',
      '  Referez-vous a packages/config, qui les declare tous.',
      '',
    ].join('\n'),
  );
  process.exit(1);
}
