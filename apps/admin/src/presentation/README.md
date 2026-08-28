# `presentation/` — les adaptateurs entrants

Les controleurs Nest, les DTO et leur validation. Traduit une requete en appel
de cas d'usage, et un resultat en reponse.

## Dependances autorisees

`application/` et `domain/`. Jamais `infrastructure/` : un controleur qui
touche la base court-circuite le metier.
