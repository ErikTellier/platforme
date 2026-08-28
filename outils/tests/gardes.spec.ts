import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  BANC D'ESSAI DES GARDE-FOUS
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  POURQUOI CE FICHIER EXISTE
 *
 *  Un garde-fou casse ne se plaint pas : il laisse passer, et tout reste vert.
 *  Trois d'entre eux ont deja ete livres inoperants dans ce depot — un
 *  resolveur manquant qui faisait ignorer TOUTES les dependances locales, un
 *  motif qui refusait la prose au lieu du code, une regex dont l'echappement
 *  avait saute et qui ne reconnaissait plus rien. Chacun etait vert.
 *
 *  On ne verifie donc pas seulement qu'un garde REFUSE ce qu'il doit refuser :
 *  on verifie aussi qu'il ACCEPTE le reste. Un garde qui refuse tout serait
 *  tout aussi casse, mais bien plus vite remarque — donc bien moins dangereux.
 *
 *  COMMENT
 *
 *  Chaque cas monte un depot git jetable, y installe LE garde comme hook, et
 *  lance un vrai `git commit`. C'est git qui invoque le script, avec son propre
 *  interpreteur : le chemin teste est exactement celui de production.
 */

const RACINE = resolve(import.meta.dirname, '..', '..');
const GARDES = join(RACINE, '.husky', 'garde');

/** Le separateur de chemin de Windows, ecrit par son code pour rester lisible. */
const SEPARATEUR = String.fromCharCode(92);

/**
 * ═══ LES DIRECTIVES SONT ASSEMBLEES, JAMAIS ECRITES EN CLAIR ═══
 *
 * Le garde teste plus bas lit le TEXTE BRUT de l'index : il ne sait pas
 * distinguer une directive d'une chaine qui lui ressemble, et c'est exactement
 * ce qui le rend increvable — on ne le contourne pas en deplacant le code.
 *
 * Consequence : ecrire ces cas en clair ferait refuser ce fichier meme. Le
 * premier jet de ce banc s'est fait bloquer par le garde qu'il teste.
 *
 * On les recompose donc a l'execution. Le depot jetable voit une vraie
 * directive ; celui-ci n'en contient aucune.
 */
const BARRE = '/';
const ETOILE = '*';

/** Une directive de ligne : `// <nom>`. */
function ligne(nom: string): string {
  return `${BARRE}${BARRE} ${nom}`;
}

/** Une directive de bloc. */
function bloc(nom: string): string {
  return `${BARRE}${ETOILE} ${nom} ${ETOILE}${BARRE}`;
}

/** Le corps anodin qui suit la directive dans chaque cas. */
const CORPS = '\nexport const a = 1;\n';

const aNettoyer: string[] = [];

afterEach(() => {
  while (aNettoyer.length > 0) {
    const chemin = aNettoyer.pop();
    if (chemin !== undefined) rmSync(chemin, { recursive: true, force: true });
  }
});

function git(depot: string, ...args: string[]): string {
  return execFileSync('git', ['-C', depot, ...args], { encoding: 'utf8' });
}

/** Un depot neuf, avec un commit initial pour que HEAD existe. */
function depotJetable(branche = 'travail'): string {
  const depot = mkdtempSync(join(tmpdir(), 'garde-'));
  aNettoyer.push(depot);

  git(depot, 'init', '--quiet', '--initial-branch', branche);
  git(depot, 'config', 'user.email', 'banc@local');
  git(depot, 'config', 'user.name', 'banc');
  git(depot, 'config', 'commit.gpgsign', 'false');

  writeFileSync(join(depot, 'depart.txt'), 'depart\n');
  git(depot, 'add', 'depart.txt');
  git(depot, 'commit', '--quiet', '--no-verify', '-m', 'depart');

  return depot;
}

/**
 * Installe UN garde comme hook pre-commit, puis tente un commit.
 *
 * Le hook DELEGUE au garde reel du depot au lieu de le recopier : un test qui
 * s'exercerait sur une copie ne dirait rien du fichier qui tourne vraiment.
 *
 * @returns le code de sortie de `git commit` : 0 accepte, non nul refuse.
 */
function tenterCommit(depot: string, garde: string): number {
  const crochets = join(depot, 'crochets');
  mkdirSync(crochets, { recursive: true });

  const chemin = join(GARDES, garde).split(SEPARATEUR).join('/');

  // Le shebang est INDISPENSABLE : sans lui, git tente de lancer le fichier
  // directement et echoue avec « cannot spawn ». Le premier jet de ce banc s'y
  // est casse, et TOUS les cas « refuse » passaient alors pour la mauvaise
  // raison — le commit echouait de toute facon. Ce sont les cas « accepte »
  // qui l'ont revele.
  writeFileSync(join(crochets, 'pre-commit'), `#!/bin/sh\nsh "${chemin}"\n`);
  git(depot, 'config', 'core.hooksPath', crochets);

  try {
    git(depot, 'commit', '-m', 'essai');
    return 0;
  } catch (erreur) {
    return (erreur as { status?: number }).status ?? 1;
  }
}

/** Ajoute un fichier a l'index, en forcant pour contourner un .gitignore. */
function indexer(depot: string, nom: string, contenu: string): void {
  writeFileSync(join(depot, nom), contenu);
  git(depot, 'add', '--force', nom);
}

describe('garde : branche protegee', () => {
  it.each(['main', 'develop'])('refuse un commit direct sur %s', (branche) => {
    const depot = depotJetable(branche);
    indexer(depot, 'a.txt', 'contenu\n');

    expect(tenterCommit(depot, 'branche-protegee.sh')).not.toBe(0);
  });

  it('accepte une branche de travail', () => {
    const depot = depotJetable('feat/quelque-chose');
    indexer(depot, 'a.txt', 'contenu\n');

    expect(tenterCommit(depot, 'branche-protegee.sh')).toBe(0);
  });
});

describe('garde : fichier d environnement', () => {
  it.each(['.env', '.env.local', '.env.production'])('refuse %s', (nom) => {
    const depot = depotJetable();
    indexer(depot, nom, 'SECRET=valeur\n');

    expect(tenterCommit(depot, 'fichier-env.sh')).not.toBe(0);
  });

  it('accepte .env.example, qui est un modele', () => {
    const depot = depotJetable();
    indexer(depot, '.env.example', 'ADMIN_PORT=3000\n');

    expect(tenterCommit(depot, 'fichier-env.sh')).toBe(0);
  });

  it('accepte un nom qui contient env sans etre un fichier d environnement', () => {
    const depot = depotJetable();
    indexer(depot, 'environnement.md', '# doc\n');

    expect(tenterCommit(depot, 'fichier-env.sh')).toBe(0);
  });
});

describe('garde : marqueur de conflit', () => {
  it('refuse un marqueur laisse dans le contenu indexe', () => {
    const depot = depotJetable();
    indexer(
      depot,
      'a.ts',
      'const a = 1;\n<<<<<<< HEAD\nconst b = 2;\n>>>>>>> autre\n',
    );

    expect(tenterCommit(depot, 'marqueur-conflit.sh')).not.toBe(0);
  });

  it('accepte du contenu ordinaire', () => {
    const depot = depotJetable();
    indexer(depot, 'a.ts', 'export const a = 1;\n');

    expect(tenterCommit(depot, 'marqueur-conflit.sh')).toBe(0);
  });
});

describe('garde : fichier demesure', () => {
  it('refuse au-dela de 2 Mio', () => {
    const depot = depotJetable();
    indexer(depot, 'gros.bin', 'x'.repeat(3 * 1024 * 1024));

    expect(tenterCommit(depot, 'fichier-demesure.sh')).not.toBe(0);
  });

  it('accepte un fichier juste en dessous de la limite', () => {
    const depot = depotJetable();
    indexer(depot, 'moyen.bin', 'x'.repeat(2 * 1024 * 1024 - 1024));

    expect(tenterCommit(depot, 'fichier-demesure.sh')).toBe(0);
  });
});

describe('garde : echappatoire au controle qualite', () => {
  it.each([
    ['bloc nu', bloc('eslint-disable') + CORPS],
    ['ligne suivante', ligne('eslint-disable-next-line no-console') + CORPS],
    ['sans verification de types', ligne('@ts-nocheck') + CORPS],
    ['sans espace', `${BARRE}${BARRE}@ts-ignore${CORPS}`],
    ['erreur attendue', ligne('@ts-expect-error') + CORPS],
    [
      'en fin de ligne',
      `export const a = 1; ${ligne('eslint-disable-line')}\n`,
    ],
  ])('refuse : %s', (_cas, contenu) => {
    const depot = depotJetable();
    indexer(depot, 'a.ts', contenu);

    expect(tenterCommit(depot, 'echappatoire.sh')).not.toBe(0);
  });

  it('accepte la prose qui documente l interdiction', () => {
    const depot = depotJetable();

    // Le mot est cite, mais ce n'est pas une directive. Le garde doit faire la
    // difference, sinon documenter la regle devient impossible. Ce cas precis a
    // deja ete un faux positif dans ce depot.
    indexer(
      depot,
      'a.ts',
      '// Une directive `eslint-disable` devenue inutile doit disparaitre.\nexport const a = 1;\n',
    );

    expect(tenterCommit(depot, 'echappatoire.sh')).toBe(0);
  });

  it('ignore les fichiers qui ne sont pas du code', () => {
    const depot = depotJetable();
    indexer(
      depot,
      'notes.md',
      `On y parle de ${ligne('@ts-nocheck')} sans en poser un.\n`,
    );

    expect(tenterCommit(depot, 'echappatoire.sh')).toBe(0);
  });
});
