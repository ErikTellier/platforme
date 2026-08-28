/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  TOUT PAQUET DOIT DECLARER SES VERROUS.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  LE TROU QUE CE FICHIER BOUCHE
 *
 *  `turbo run test` n'execute que les paquets qui DECLARENT un script `test`.
 *  Un paquet qui n'en declare pas n'echoue pas : il est ignore, en silence, et
 *  turbo annonce meme un succes. Creer `apps/facturation` sans script `test`
 *  suffisait donc a traverser tout le harnais sans qu'une seule ligne de code
 *  soit verifiee.
 *
 *  Un verrou qu'on peut eviter en ne le declarant pas n'est pas un verrou.
 *
 *  CE QUI EST EXIGE DEPEND DE CE QUE LE PAQUET CONTIENT
 *
 *  Un paquet qui n'expose que du JSON — `typescript-config` — n'a rien a
 *  linter ni a tester. Une exigence uniforme forcerait a ecrire des scripts
 *  vides, et un script vide est exactement le vert qui ne prouve rien.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const racine = resolve(import.meta.dirname, '..');
const GROUPES = ['apps', 'packages'];
/** Le separateur de chemin de Windows. Ecrit par son code pour rester lisible. */
const SEPARATEUR = String.fromCharCode(92);

const IGNORES = new Set([
  'node_modules',
  'dist',
  'coverage',
  '.stryker-tmp',
  'reports',
]);

/** Fichiers du paquet, sans les dossiers engendres. */
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

/** Liste les paquets du depot, tels que pnpm-workspace.yaml les designe. */
function paquets() {
  return GROUPES.flatMap((groupe) => {
    const base = join(racine, groupe);
    if (!existsSync(base)) return [];
    return readdirSync(base, { withFileTypes: true })
      .filter((entree) => entree.isDirectory())
      .map((entree) => join(base, entree.name))
      .filter((chemin) => existsSync(join(chemin, 'package.json')));
  });
}

const anomalies = [];

/** @param {string} paquet @param {string} probleme */
function signaler(paquet, probleme) {
  const nom = paquet
    .slice(racine.length + 1)
    .split(SEPARATEUR)
    .join('/');
  anomalies.push(`  ${nom} : ${probleme}`);
}

for (const paquet of paquets()) {
  const manifeste = JSON.parse(
    readFileSync(join(paquet, 'package.json'), 'utf8'),
  );
  const scripts = manifeste.scripts ?? {};
  const fichiers = fichiersDe(paquet);

  const aDuCodeLintable = fichiers.some((f) =>
    ['.ts', '.js', '.mjs', '.cjs'].some((ext) => f.endsWith(ext)),
  );
  const aDesSources = fichiers.some(
    (f) => f.startsWith('src/') && f.endsWith('.ts') && !f.endsWith('.spec.ts'),
  );

  // ─── Tout code lintable se lint et se type-verifie ───
  if (aDuCodeLintable) {
    for (const requis of ['lint', 'typecheck']) {
      if (!scripts[requis]) signaler(paquet, `script "${requis}" manquant`);
    }
  }

  if (!aDesSources) continue;

  // ─── Un paquet qui porte du code metier le PROUVE ───
  for (const requis of ['build', 'test', 'mutation']) {
    if (!scripts[requis]) signaler(paquet, `script "${requis}" manquant`);
  }

  // Declarer `test` ne suffit pas : `echo ok` passerait. On exige la mesure.
  if (scripts.test && !scripts.test.includes('--coverage')) {
    signaler(
      paquet,
      'le script "test" ne mesure pas la couverture (--coverage)',
    );
  }

  const vitest = join(paquet, 'vitest.config.ts');
  if (!existsSync(vitest)) {
    signaler(paquet, 'vitest.config.ts manquant');
  } else {
    const contenu = readFileSync(vitest, 'utf8');
    if (!contenu.includes('thresholds')) {
      signaler(paquet, 'vitest.config.ts ne fixe aucun seuil de couverture');
    }
    // Sans `perFile`, une moyenne flatteuse masque un fichier entierement nu.
    if (!contenu.includes('perFile')) {
      signaler(paquet, 'seuils de couverture sans "perFile"');
    }
    // On cherche le REGLAGE, pas le mot : un commentaire qui explique son
    // retrait ne doit pas declencher le refus. Sans regex — les echappements
    // s'y perdent trop facilement, et un motif casse ici ne signalerait plus
    // rien, en silence.
    if (contenu.split(' ').join('').includes('passWithNoTests:')) {
      signaler(
        paquet,
        '"passWithNoTests" rend le banc vert sans rien executer',
      );
    }
  }

  const stryker = join(paquet, 'stryker.config.json');
  if (!existsSync(stryker)) {
    signaler(paquet, 'stryker.config.json manquant');
  } else {
    const config = JSON.parse(readFileSync(stryker, 'utf8'));
    if (config.thresholds?.break == null) {
      signaler(
        paquet,
        'stryker.config.json sans seuil bloquant ("thresholds.break")',
      );
    }
  }
}

if (anomalies.length > 0) {
  process.stderr.write(
    [
      '',
      'REFUS : un paquet ne declare pas tous ses verrous.',
      '',
      ...anomalies,
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
