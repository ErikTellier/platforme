// @ts-check
import eslint from '@eslint/js';
// `defineConfig` du COEUR d'ESLint, et non `tseslint.config` : ce dernier est
// deprecie depuis que la fonctionnalite a rejoint ESLint lui-meme. C'est la
// regle `no-deprecated` de ce fichier qui l'a signale, applique a lui-meme.
import { defineConfig } from 'eslint/config';
import { createTypeScriptImportResolver } from 'eslint-import-resolver-typescript';
import { importX } from 'eslint-plugin-import-x';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import sonarjs from 'eslint-plugin-sonarjs';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/**
 * Configuration ESLint severe, commune a tout paquet TypeScript du depot.
 *
 * C'est une FONCTION et non un tableau, pour une seule raison : les regles
 * typees ont besoin de `tsconfigRootDir`, qui vaut le dossier du PAQUET qui
 * l'appelle. Exporter un tableau tout fait ferait pointer chaque paquet vers le
 * tsconfig de la configuration partagee — les regles typees se tairaient alors
 * sans rien signaler.
 *
 * @param {{ tsconfigRootDir: string }} options
 * @returns {import('eslint').Linter.Config[]}
 */
export function base({ tsconfigRootDir }) {
  return defineConfig(
    {
      // Une directive `eslint-disable` devenue inutile est la trace d'un code
      // qu'on a fait taire puis corrige : elle doit disparaitre avec lui.
      // Le blocage des directives ACTIVES ne peut pas vivre ici — une telle
      // directive coupe ESLint avant toute regle. Voir .husky/pre-commit,
      // section 6.
      linterOptions: {
        reportUnusedDisableDirectives: 'error',
      },
    },
    { ignores: ['dist/**', 'coverage/**', 'eslint.config.mjs'] },
    eslint.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    ...tseslint.configs.stylisticTypeChecked,
    sonarjs.configs.recommended,
    importX.flatConfigs.recommended,
    importX.flatConfigs.typescript,
    eslintPluginPrettierRecommended,
    {
      languageOptions: {
        globals: { ...globals.node },
        sourceType: 'module',
        parserOptions: { projectService: true, tsconfigRootDir },
      },
      settings: {
        // Le depot ecrit `import './config.js'` pour un fichier `config.ts`,
        // comme l'exige `nodenext`. Un resolveur Node nu ne trouverait rien, et
        // les regles de graphe se tairaient en croyant tout verifier.
        'import-x/resolver-next': [
          createTypeScriptImportResolver({
            project: tsconfigRootDir,
            alwaysTryTypes: true,
          }),
        ],
      },
    },
    {
      rules: {
        'prettier/prettier': 'error',

        // ═══ TAILLE ET COMPLEXITE ═══
        //
        // Ces bornes ne visent pas l'elegance : elles visent ce qu'un humain
        // peut tenir en tete d'un seul coup. Une fonction qui les depasse se
        // relit mal, donc se corrige mal, donc casse.
        //
        // La complexite COGNITIVE de sonarjs prime sur la cyclomatique : elle
        // pese ce qui est reellement dur a suivre — imbrication, ruptures de
        // flux — la ou la cyclomatique compte betement les branches.
        'sonarjs/cognitive-complexity': ['error', 15],
        complexity: ['error', 10],
        'max-depth': ['error', 3],
        'max-params': ['error', 4],
        'max-lines': [
          'error',
          { max: 300, skipBlankLines: true, skipComments: true },
        ],
        'max-lines-per-function': [
          'error',
          { max: 60, skipBlankLines: true, skipComments: true },
        ],
        'max-nested-callbacks': ['error', 3],

        // ═══ GRAPHE DE MODULES ═══
        //
        // Un cycle d'imports ne casse rien tant qu'il est petit, puis rend
        // l'ordre d'initialisation imprevisible — et le symptome apparait
        // toujours ailleurs que la cause.
        'import-x/no-cycle': ['error', { maxDepth: Infinity }],
        'import-x/no-self-import': 'error',
        'import-x/no-useless-path-segments': 'error',

        // Faux positif connu avec les greffons ESLint en configuration plate :
        // ils exposent `configs` a la fois en export par defaut et en export
        // nomme, et la regle croit y voir une confusion.
        'import-x/no-named-as-default-member': 'off',

        // Un service journalise par son logger, jamais par la console : un
        // `console.log` en production n'a ni niveau, ni contexte, ni
        // destination maitrisee.
        'no-console': 'error',
      },
    },
    {
      // Un type de retour explicite sur ce qui est EXPORTE. Sans lui,
      // l'inference change le contrat public au gre d'une modification
      // interne, sans qu'aucune ligne du contrat n'ait bouge.
      //
      // Limite au TypeScript : en JS annote par JSDoc, la meme exigence se paie
      // en bruit sans rien garantir de plus.
      files: ['**/*.ts'],
      rules: {
        '@typescript-eslint/explicit-module-boundary-types': 'error',
      },
    },
    {
      // ═══ UNE CONFIGURATION EST UNE DONNEE, PAS UN ALGORITHME ═══
      //
      // Les `.js` de ce depot sont tous des fichiers de configuration : leurs
      // fonctions ne sont qu'un emballage recevant `tsconfigRootDir` autour
      // d'un litteral. Compter leurs lignes reviendrait a compter des lignes de
      // donnees, pas de la complexite.
      //
      // Tout le code applicatif est en `.ts`, ou les bornes restent actives.
      files: ['**/*.js', '**/*.mjs'],
      rules: {
        'max-lines-per-function': 'off',
        'max-lines': 'off',
      },
    },
    {
      // ═══ LES TESTS SONT DU CODE, MAIS PAS LE MEME ═══
      //
      // Un test decrit des CAS : il est repetitif par nature, et le forcer a
      // etre DRY le rend moins lisible, donc moins fiable comme reference.
      files: ['**/*.spec.ts'],
      rules: {
        'sonarjs/no-duplicate-string': 'off',
        'max-lines': 'off',
        'max-lines-per-function': 'off',
        'max-nested-callbacks': 'off',
        '@typescript-eslint/explicit-module-boundary-types': 'off',
      },
    },
  );
}
