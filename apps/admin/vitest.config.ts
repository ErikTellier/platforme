import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.spec.ts'],
    environment: 'node',

    // PROVISOIRE — a retirer des le premier vrai test.
    //
    // Sans ca, `vitest run` sort en erreur quand il ne trouve aucun fichier.
    // Avec, `pnpm test` rend vert un banc qui n'execute RIEN : la seule chose
    // que ce vert prouve aujourd'hui, c'est qu'il n'y a rien a prouver.
    passWithNoTests: true,
  },
});
