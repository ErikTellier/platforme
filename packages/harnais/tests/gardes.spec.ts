import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

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

/**
 * La racine du depot, trouvee en REMONTANT jusqu'au marqueur.
 *
 * Et non `resolve(dirname, '..', '..')` : compter les niveaux encode la
 * profondeur du paquet, et se trompe en silence le jour ou il demenage — ce qui
 * vient precisement d'arriver a ce fichier, passe de outils/ a packages/.
 */
function racineDuDepot(depuis: string): string {
  let courant = resolve(depuis);

  for (;;) {
    if (existsSync(join(courant, 'pnpm-workspace.yaml'))) return courant;

    const parent = dirname(courant);
    if (parent === courant)
      throw new Error(`Racine introuvable depuis ${depuis}.`);
    courant = parent;
  }
}

const RACINE = racineDuDepot(import.meta.dirname);
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

/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  LE CYCLE DE VIE DU JETON ANTI-CONTOURNEMENT
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  `--no-verify` saute `pre-commit` et `commit-msg`, mais pas `post-commit`.
 *  Le second depose un jeton, le troisieme le cherche : son absence trahit le
 *  contournement, et le commit est defait.
 *
 *  Tout le danger est dans les chemins ou le jeton SURVIT sans etre consomme —
 *  il devient alors un laissez-passer pour le commit suivant. Une fusion en
 *  ouvrait un : git y lance `post-merge` et non `post-commit`. Bug reel, trouve
 *  en preparant un simple `merge --no-ff`.
 *
 *  On installe ici les VRAIS `poser-jeton.sh` et `post-commit`, pas des copies.
 */
describe('jeton anti-contournement', () => {
  /** Monte un depot ou commit-msg pose le jeton et post-commit le consomme. */
  function depotArme(branche = 'travail'): string {
    const depot = depotJetable(branche);
    const crochets = join(depot, 'crochets');
    mkdirSync(crochets, { recursive: true });

    const poseur = join(GARDES, 'poser-jeton.sh').split(SEPARATEUR).join('/');
    const apres = join(RACINE, '.husky', 'post-commit')
      .split(SEPARATEUR)
      .join('/');
    const fusion = join(RACINE, '.husky', 'post-merge')
      .split(SEPARATEUR)
      .join('/');

    writeFileSync(join(crochets, 'commit-msg'), `#!/bin/sh\nsh "${poseur}"\n`);
    writeFileSync(join(crochets, 'post-commit'), `#!/bin/sh\nsh "${apres}"\n`);
    writeFileSync(join(crochets, 'post-merge'), `#!/bin/sh\nsh "${fusion}"\n`);
    git(depot, 'config', 'core.hooksPath', crochets);

    return depot;
  }

  /** Le jeton restant dans .git, s'il y en a un. */
  function jetonPresent(depot: string): boolean {
    return existsSync(join(depot, '.git', 'harnais-valide'));
  }

  function nombreDeCommits(depot: string): number {
    return Number(git(depot, 'rev-list', '--count', 'HEAD').trim());
  }

  it('conserve un commit normal', () => {
    const depot = depotArme();
    indexer(depot, 'a.txt', 'contenu\n');
    const avant = nombreDeCommits(depot);

    git(depot, 'commit', '-m', 'normal');

    expect(nombreDeCommits(depot)).toBe(avant + 1);
    expect(jetonPresent(depot)).toBe(false);
  });

  it('defait un commit passe en --no-verify, sans perdre le travail', () => {
    const depot = depotArme();
    indexer(depot, 'a.txt', 'contenu\n');
    const avant = nombreDeCommits(depot);

    git(depot, 'commit', '--no-verify', '-m', 'contourne');

    expect(nombreDeCommits(depot)).toBe(avant);
    // Le travail doit rester INDEXE : on defait le commit, pas le travail.
    expect(git(depot, 'diff', '--cached', '--name-only')).toContain('a.txt');
  });

  it('ne laisse aucun jeton derriere une fusion', () => {
    const depot = depotArme('develop');

    // Preparation avec de VRAIS commits. Un `--no-verify` ici serait defait par
    // post-commit : la branche resterait vide, la fusion n'aurait rien a
    // fusionner, et le cas passerait au vert sans rien eprouver. Piege tombe
    // une premiere fois en ecrivant ce banc.
    git(depot, 'switch', '--quiet', '-c', 'sujet');
    indexer(depot, 'sujet.txt', 'sujet\n');
    git(depot, 'commit', '-m', 'sujet');
    git(depot, 'switch', '--quiet', 'develop');

    git(depot, 'merge', '--no-ff', 'sujet', '-m', 'Merge branch sujet');

    expect(jetonPresent(depot)).toBe(false);
  });

  it('defait un --no-verify pose juste apres une fusion', () => {
    const depot = depotArme('develop');
    git(depot, 'switch', '--quiet', '-c', 'sujet');
    indexer(depot, 'sujet.txt', 'sujet\n');
    git(depot, 'commit', '--no-verify', '-m', 'sujet');
    git(depot, 'switch', '--quiet', 'develop');
    git(depot, 'merge', '--no-ff', 'sujet', '-m', 'Merge branch sujet');

    indexer(depot, 'apres.txt', 'apres\n');
    const avant = nombreDeCommits(depot);

    git(depot, 'commit', '--no-verify', '-m', 'profite de la fusion');

    expect(nombreDeCommits(depot)).toBe(avant);
  });

  it("conserve le commit quand l'echappatoire est demandee explicitement", () => {
    const depot = depotArme();
    indexer(depot, 'a.txt', 'contenu\n');
    const avant = nombreDeCommits(depot);

    execFileSync(
      'git',
      ['-C', depot, 'commit', '--no-verify', '-m', 'assume'],
      {
        encoding: 'utf8',
        env: { ...process.env, HARNAIS_DESACTIVE: '1' },
      },
    );

    expect(nombreDeCommits(depot)).toBe(avant + 1);
  });
  // ═══ CAS NON COUVERT ICI : LA FUSION RESOLUE A LA MAIN ═══
  //
  // `post-commit` refuse de defaire un commit a plusieurs parents. Sans cette
  // protection, une fusion conflictuelle resolue par `git commit` se faisait
  // ANNULER : commit-msg voit MERGE_HEAD et n'y pose pas de jeton, mais git a
  // deja efface MERGE_HEAD quand post-commit s'execute.
  //
  // Le cas est verifie A LA MAIN, par reproduction directe : sans le comptage
  // des parents la fusion disparait, avec lui elle survit.
  //
  // Il n'est PAS ici parce que je n'ai pas su le faire tenir dans ce banc — la
  // preparation d'un vrai conflit y produisait un commit ordinaire, et le cas
  // passait au vert des deux cotes. Un test qui ne peut pas rougir vaut moins
  // que pas de test : il fait croire que la regression serait vue.
});
