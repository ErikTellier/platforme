/**
 * Ce qui tourne sur les fichiers INDEXES, et eux seuls.
 *
 * lint-staged met de cote la partie NON indexee d'un fichier partiellement
 * ajoute (`git add -p`) avant de lancer ces commandes, puis la remet. Sans ca,
 * prettier reecrirait le fichier entier et le hook indexerait au passage du
 * travail que vous n'aviez pas choisi de commiter.
 *
 * ESLint n'est PAS ici : la configuration plate se resout par PAQUET, il n'y a
 * pas d'eslint.config.mjs a la racine. Le lint typé tourne au niveau du paquet,
 * via `turbo run lint` dans le pre-commit.
 */
export default {
  // Tout ce que prettier sait lire. Les fichiers cites dans .prettierignore
  // sont ignores en silence, il n'y a rien a exclure ici.
  '*.{ts,js,mjs,cjs,json,md,yml,yaml}': ['prettier --write'],

  // Recherche de secrets sur TOUT fichier indexe, sans filtre d'extension :
  // une cle peut aussi bien atterrir dans un .txt que dans un .ts.
  '*': ['secretlint --maskSecrets --secretlintignore .gitignore'],
};
