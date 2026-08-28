# `infrastructure/` — les adaptateurs sortants

Les implementations concretes des ports du domaine : base de donnees, files de
messages, clients HTTP, horloge, generateur d'identifiants.

## Dependances autorisees

`domain/` et `application/`. C'est ici, et seulement ici, que vivent les
bibliotheques d'entree-sortie.
