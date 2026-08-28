# Un `<<<<<<<` commite casse le fichier pour tout le monde, et se decouvre
# toujours chez quelqu'un d'autre.
conflits=$(git diff --cached -U0 | grep -nE '^\+(<{7}|>{7})' || true)

if [ -n "$conflits" ]; then
  echo "" >&2
  echo "REFUS : marqueur de conflit dans le contenu indexe." >&2
  echo "" >&2
  echo "$conflits" | head -10 | sed 's/^/    /' >&2
  echo "" >&2
  exit 1
fi
