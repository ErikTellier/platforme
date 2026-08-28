// @ts-check
import { defineConfig } from 'eslint/config';

import { base } from './base.js';

/**
 * `base`, plus la seule exception que NestJS impose.
 *
 * @param {{ tsconfigRootDir: string }} options
 */
export function nest({ tsconfigRootDir }) {
  return defineConfig(...base({ tsconfigRootDir }), {
    // Un module Nest EST une classe vide : le corps ne sert a rien, la classe
    // n'existe que comme jeton d'injection porte par @Module. La regle a donc
    // structurellement tort ici, et seulement ici — elle reste active partout
    // ailleurs, ou une classe sans membre est bien un defaut.
    files: ['**/*.module.ts'],
    rules: {
      '@typescript-eslint/no-extraneous-class': 'off',
    },
  });
}
