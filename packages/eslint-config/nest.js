// @ts-check
import { defineConfig } from 'eslint/config';
import boundariesBrut from 'eslint-plugin-boundaries';

import { base } from './base.js';

/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  ARCHITECTURE HEXAGONALE — les dependances pointent vers l'INTERIEUR.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *    presentation ──┐
 *                   ├──> application ──> domain
 *    infrastructure ┘                      ▲
 *                   └──────────────────────┘
 *
 *  Le domaine est au centre et ne connait personne. Tout le reste le connait.
 *
 *  CE QUE CETTE INVERSION ACHETE : le metier se teste sans base de donnees,
 *  sans serveur HTTP et sans Nest. Un test du domaine demarre en seize
 *  millisecondes et ne peut pas echouer pour une raison d'infrastructure.
 *
 *  L'ORDRE COMPTE : le premier motif qui correspond gagne. `test` vient donc en
 *  tete, sinon `domain/x.spec.ts` serait classe `domain` et se verrait
 *  interdire d'importer vitest.
 */
// Le greffon n'expose pas le type `Plugin` d'ESLint — sa forme est pourtant
// conforme. Transtypage JSDoc, et non `@ts-expect-error` : le garde-fou du
// pre-commit interdit ce dernier, a juste titre, puisqu'il masquerait aussi
// toute erreur future a cet endroit.
const boundaries = /** @type {import('eslint').ESLint.Plugin} */ (
  boundariesBrut
);

const elements = [
  { type: 'test', pattern: 'src/**/*.spec.ts', partialMatch: false },
  { type: 'domain', pattern: 'src/domain/**' },
  { type: 'application', pattern: 'src/application/**' },
  { type: 'infrastructure', pattern: 'src/infrastructure/**' },
  { type: 'presentation', pattern: 'src/presentation/**' },

  // La racine de composition : `main.ts`, `app.module.ts`, `config.ts`. Seul
  // endroit autorise a tout connaitre, puisque son role est precisement
  // d'assembler les couches entre elles.
  { type: 'composition', pattern: 'src/*.ts', partialMatch: false },
];

/**
 * Raccourci : dependance vers une couche interne.
 *
 * @param {string} type
 */
const couche = (type) => ({ to: { element: { type } } });

/**
 * Raccourci : dependance vers un paquet externe ou un module de Node.
 *
 * @param {string} [source] Restreint a ce paquet ; sinon, tous.
 */
const externe = (source) => ({
  to: {
    module: { origin: ['external', 'core'], ...(source ? { source } : {}) },
  },
});

/**
 * `base`, plus les frontieres d'architecture et la seule exception que NestJS
 * impose.
 *
 * @param {{ tsconfigRootDir: string }} options
 */
export function nest({ tsconfigRootDir }) {
  return defineConfig(
    ...base({ tsconfigRootDir }),
    {
      settings: {
        'boundaries/elements': elements,
        'import/resolver': { typescript: { alwaysTryTypes: true } },
      },
      plugins: { boundaries },
      rules: {
        'boundaries/dependencies': [
          'error',
          {
            // Sans ca, les paquets externes echappent a la regle — et c'est
            // precisement par eux que le framework s'invite dans le domaine.
            checkAllOrigins: true,
            default: 'disallow',

            policies: [
              // ═══ LE DOMAINE ═══
              //
              // Le coeur de l'hexagone. `zod` est la SEULE dependance externe
              // toolerée : il decrit des invariants de donnees — ce qui est du
              // domaine — et n'ouvre aucune entree-sortie.
              //
              // Un `import { Injectable } from '@nestjs/common'` ici fait
              // rougir le lint. C'est la ligne qui tient tout l'edifice.
              {
                from: { element: { type: 'domain' } },
                allow: [couche('domain'), externe('zod')],
              },

              // ═══ LES CAS D'USAGE ═══
              //
              // Orchestrent le domaine. Ils declarent leurs besoins sous forme
              // de ports et ne savent jamais QUI les implemente.
              {
                from: { element: { type: 'application' } },
                allow: [couche('domain'), couche('application'), externe()],
              },

              // ═══ LES ADAPTATEURS SORTANTS ═══
              {
                from: { element: { type: 'infrastructure' } },
                allow: [
                  couche('domain'),
                  couche('application'),
                  couche('infrastructure'),
                  externe(),
                ],
              },

              // ═══ LES ADAPTATEURS ENTRANTS ═══
              //
              // Pas d'acces a `infrastructure` : un controleur qui touche la
              // base court-circuite le metier, et le cas d'usage devient un
              // decor.
              {
                from: { element: { type: 'presentation' } },
                allow: [
                  couche('domain'),
                  couche('application'),
                  couche('presentation'),
                  externe(),
                ],
              },

              // ═══ RACINE DE COMPOSITION ET TESTS ═══
              {
                from: { element: { type: 'composition' } },
                allow: [
                  couche('domain'),
                  couche('application'),
                  couche('infrastructure'),
                  couche('presentation'),
                  couche('composition'),
                  externe(),
                ],
              },
              {
                from: { element: { type: 'test' } },
                allow: [
                  couche('domain'),
                  couche('application'),
                  couche('infrastructure'),
                  couche('presentation'),
                  couche('composition'),
                  couche('test'),
                  externe(),
                ],
              },
            ],
          },
        ],
      },
    },
    {
      // Un module Nest EST une classe vide : le corps ne sert a rien, la classe
      // n'existe que comme jeton d'injection porte par @Module. La regle a donc
      // structurellement tort ici, et seulement ici — elle reste active partout
      // ailleurs, ou une classe sans membre est bien un defaut.
      files: ['**/*.module.ts'],
      rules: {
        '@typescript-eslint/no-extraneous-class': 'off',
      },
    },
  );
}
