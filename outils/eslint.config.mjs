import { base } from '@platforme/eslint-config/base';

export default [
  ...base({ tsconfigRootDir: import.meta.dirname }),
  {
    // ═══ LA SEULE EXCEPTION DE CE PAQUET ═══
    //
    // `sonarjs/no-os-command-from-path` veut un chemin absolu pour tout binaire
    // appele : un PATH modifiable permettrait d'y glisser un faux `git`. La
    // regle a raison en production.
    //
    // Ici, le banc d'essai DOIT piloter le git de la machine — c'est tout son
    // objet : verifier que git invoque bien nos gardes. Coder son chemin en dur
    // le rendrait faux d'un poste a l'autre.
    //
    // Posee ici et non dans la configuration partagee : elle ne vaut que pour
    // ce banc, et doit rougir partout ailleurs.
    files: ['tests/**/*.spec.ts'],
    rules: {
      'sonarjs/no-os-command-from-path': 'off',
    },
  },
];
