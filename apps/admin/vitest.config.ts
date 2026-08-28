import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.spec.ts'],
    environment: 'node',

    // `passWithNoTests` a ete RETIRE. Il rendait `pnpm test` vert sur un banc
    // qui n'executait rien : la seule chose que ce vert prouvait, c'est qu'il
    // n'y avait rien a prouver. Sans lui, un paquet sans test echoue.

    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text-summary'],

      exclude: [
        'src/**/*.spec.ts',

        // ═══ CE QUI EST EXCLU, ET POURQUOI ═══
        //
        // La racine de composition. `main.ts` n'a pas de logique : il assemble
        // et ecoute. `app.module.ts` est une classe vide portant un decorateur.
        //
        // Les couvrir demanderait un test qui les IMPORTE sans rien affirmer —
        // le chiffre monterait, la garantie resterait nulle. C'est exactement
        // la couverture de facade que les seuils sont censes empecher.
        //
        // Ce qu'ils font se verifie autrement : `nest build` compile, et un
        // demarrage rate se voit immediatement.
        'src/main.ts',
        'src/app.module.ts',
      ],

      // Voir packages/config/vitest.config.ts : `perFile` est ce qui empeche
      // une moyenne flatteuse de masquer un fichier nu.
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
