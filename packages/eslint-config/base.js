// @ts-check
import eslint from '@eslint/js';
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
  return tseslint.config(
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
