# `application/` — les cas d'usage

Orchestre le domaine pour repondre a une intention metier. Un cas d'usage par
fichier, nomme par ce qu'il fait.

## Dependances autorisees

`domain/` uniquement. L'application declare ce dont elle a besoin sous forme de
ports ; elle ne sait jamais QUI les implemente.
