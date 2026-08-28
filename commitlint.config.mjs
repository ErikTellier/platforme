import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * ═══ LES PORTEES SE DEDUISENT, ELLES NE SE RECOPIENT PAS ═══
 *
 * Une liste ecrite en dur serait fausse le jour ou un service apparait, et
 * personne ne penserait a la mettre a jour AVANT d'en avoir besoin. On lit donc
 * les dossiers de `apps/` et `packages/`, exactement comme pnpm-workspace.yaml.
 */
const racine = import.meta.dirname;

const paquets = ['apps', 'packages'].flatMap((groupe) => {
  const base = join(racine, groupe);
  if (!existsSync(base)) return [];
  return readdirSync(base, { withFileTypes: true })
    .filter((entree) => entree.isDirectory())
    .map((entree) => entree.name);
});

/** Portees hors paquet : le depot lui-meme, et ses dependances. */
const horsPaquet = ['repo', 'deps', 'harnais'];

const portees = [...paquets, ...horsPaquet].sort();

export default {
  extends: ['@commitlint/config-conventional'],

  rules: {
    // ─── Le type ───
    //
    // Liste FERMEE. `config-conventional` en accepte davantage ; on retire ceux
    // qui ne veulent rien dire ici (`style`, que prettier rend impossible) et on
    // garde ce qui se lit dans un journal.
    'type-enum': [
      2,
      'always',
      [
        'feat',
        'fix',
        'perf',
        'refactor',
        'docs',
        'test',
        'build',
        'chore',
        'revert',
      ],
    ],

    // ─── La portee est OBLIGATOIRE ───
    //
    // En monorepo, « fix: corriger le demarrage » ne dit pas QUOI. La portee
    // repond a la seule question qui compte en relisant : ou ?
    'scope-empty': [2, 'never'],
    'scope-enum': [2, 'always', portees],

    // ─── Le sujet ───
    'subject-case': [2, 'always', 'lower-case'],
    'subject-full-stop': [2, 'never', '.'],
    'subject-min-length': [2, 'always', 12],
    'subject-empty': [2, 'never'],

    // 72 et non 100 : au-dela, `git log --oneline` tronque et l'information
    // utile disparait exactement quand on la cherche.
    'header-max-length': [2, 'always', 72],

    // ─── Le corps, quand il existe ───
    'body-leading-blank': [2, 'always'],
    'body-max-line-length': [2, 'always', 100],
    'footer-leading-blank': [2, 'always'],
  },
};
