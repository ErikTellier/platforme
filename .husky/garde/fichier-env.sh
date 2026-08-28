# Aucun fichier d'environnement n'entre dans l'historique.
#
# Le .gitignore suffit tant que personne n'ecrit `git add -f`. Ce controle vise
# ce cas : un secret pousse se revoque, il ne s'efface pas. `.env.example` est
# le seul autorise, c'est un modele et il ne contient rien.
indexes=$(git diff --cached --name-only --diff-filter=ACM |
  grep -E '(^|/)\.env($|\.)' |
  grep -vE '(^|/)\.env\.example$' || true)

if [ -n "$indexes" ]; then
  echo "" >&2
  echo "REFUS : un fichier d'environnement est indexe." >&2
  echo "" >&2
  echo "$indexes" | sed 's/^/    /' >&2
  echo "" >&2
  echo "  Retirez-le :  git restore --staged <fichier>" >&2
  echo "" >&2
  exit 1
fi
