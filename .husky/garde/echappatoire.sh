# ═══ POURQUOI CE CONTROLE N'EST PAS DANS ESLINT ═══
#
# On ne peut pas demander a ESLint d'interdire l'interrupteur qui l'eteint :
# `/* eslint-disable */` coupe le linter AVANT que la moindre regle ne tourne,
# `ban-ts-comment` compris. Et `tsc` n'offre aucune option pour refuser un
# `@ts-nocheck`.
#
# Mesure faite : un fichier portant ces deux lignes, avec un parametre non type
# et un `any`, passait `pnpm lint` ET `pnpm build` sans une seule erreur.
#
# Le mot-cle doit SUIVRE l'ouverture du commentaire : la prose qui documente
# l'interdiction — celle-ci comprise — doit pouvoir la nommer.
trouvees=$(git diff --cached -U0 -- '*.ts' '*.js' '*.mjs' '*.cjs' |
  grep -E '^\+.*(//|/\*+)[[:space:]]*(eslint-disable|@ts-ignore|@ts-nocheck|@ts-expect-error)' || true)

if [ -n "$trouvees" ]; then
  echo "" >&2
  echo "REFUS : echappatoire au controle qualite dans le code indexe." >&2
  echo "" >&2
  echo "$trouvees" | head -10 | sed 's/^/    /' >&2
  echo "" >&2
  echo "  Ces commentaires eteignent le linter ou le verificateur de types." >&2
  echo "  Le code doit satisfaire les regles, pas les faire taire." >&2
  echo "" >&2
  echo "  Si une regle est vraiment inadaptee, elle se desactive dans la" >&2
  echo "  configuration PARTAGEE, avec un motif ecrit — jamais dans un fichier." >&2
  echo "" >&2
  exit 1
fi
