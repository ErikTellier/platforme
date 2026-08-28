# Un binaire commite par megarde reste dans l'historique POUR TOUJOURS : le
# retirer demande de reecrire toutes les branches. On refuse en amont.
limite=2097152 # 2 Mio

gros=$(git diff --cached --name-only --diff-filter=ACM | while read -r fichier; do
  [ -f "$fichier" ] || continue
  taille=$(wc -c <"$fichier")
  if [ "$taille" -gt "$limite" ]; then
    echo "    $fichier — $((taille / 1024)) Kio"
  fi
done)

if [ -n "$gros" ]; then
  echo "" >&2
  echo "REFUS : fichier de plus de 2 Mio indexe." >&2
  echo "" >&2
  echo "$gros" >&2
  echo "" >&2
  echo "  L'historique git est definitif : un binaire y reste meme supprime." >&2
  echo "" >&2
  exit 1
fi
