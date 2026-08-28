import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.spec.ts'],
    environment: 'node',

    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.spec.ts'],
      reporter: ['text-summary'],

      // ═══ LES SEUILS SONT LE VRAI VERROU ═══
      //
      // `perFile: true` est la ligne qui compte. Sans elle, une moyenne globale
      // se satisfait d'un fichier couvert a fond et d'un autre laisse nu — et
      // c'est exactement ce que produit quelqu'un qui vise le chiffre plutot
      // que la preuve.
      //
      // 100 parce que ce paquet est petit et qu'il decide du DEMARRAGE de tous
      // les services : une branche non testee ici est un service qui refuse de
      // demarrer en production pour une raison que personne n'a jamais lue.
      thresholds: {
        perFile: true,
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100,
      },
    },
  },
});
