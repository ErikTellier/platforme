// @ts-check
import eslint from '@eslint/js';
// `defineConfig` du COEUR d'ESLint, et non `tseslint.config` : ce dernier est
// deprecie depuis que la fonctionnalite a rejoint ESLint lui-meme. C'est la
// regle `no-deprecated` de ce fichier qui l'a signale, applique a lui-meme.
import { defineConfig } from 'eslint/config';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
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
 */
export function base({ tsconfigRootDir }) {
  return defineConfig(
    {
      // Une directive `eslint-disable` devenue inutile est la trace d'un code
      // qu'on a fait taire puis corrige : elle doit disparaitre avec lui.
      // Le blocage des directives ACTIVES ne peut pas vivre ici — un
      // `eslint-disable` coupe ESLint avant toute regle. Voir
      // .husky/pre-commit, section 6.
      linterOptions: {
        reportUnusedDisableDirectives: 'error',
      },
    },
    {
      ignores: ['dist/**', 'eslint.config.mjs'],
    },
    eslint.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    ...tseslint.configs.stylisticTypeChecked,
    eslintPluginPrettierRecommended,
    {
      languageOptions: {
        globals: { ...globals.node },
        sourceType: 'module',
        parserOptions: {
          projectService: true,
          tsconfigRootDir,
        },
      },
    },
    {
      rules: {
        'prettier/prettier': 'error',
      },
    },
  );
}
