import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.spec.ts'],
    environment: 'node',

    // Chaque cas cree un depot git jetable et lance un vrai `git commit` :
    // c'est plus lent qu'un test unitaire, et c'est le prix de verifier le
    // chemin REEL par lequel git invoque un hook.
    testTimeout: 30_000,
  },
});
