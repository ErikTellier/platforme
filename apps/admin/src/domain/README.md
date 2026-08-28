# `domain/` — le centre de l'hexagone

Les entites, les objets-valeurs et les **ports** (interfaces que
l'infrastructure devra implementer).

## Ce qui est interdit ici

Toute dependance exterieure, `zod` excepte. Pas de `@nestjs/*`, pas de client
de base de donnees, pas de HTTP. Le lint le refuse.

`zod` fait exception parce qu'il decrit des invariants de donnees — ce qui est
du domaine — et n'ouvre aucune entree-sortie.

## Pourquoi cette severite

Un domaine sans dependance se teste en millisecondes, sans base ni serveur, et
ne peut pas echouer pour une raison d'infrastructure. C'est tout ce que
l'hexagone achete.
