# Refuse un commit direct sur une branche qui ne recoit que des fusions.
branche=$(git rev-parse --abbrev-ref HEAD)

case "$branche" in
main | develop)
  echo "" >&2
  echo "REFUS : commit direct sur '$branche'." >&2
  echo "" >&2
  echo "  Ces branches ne recoivent que des fusions. Travaillez en branche :" >&2
  echo "    git switch -c type/sujet" >&2
  echo "" >&2
  exit 1
  ;;
esac
