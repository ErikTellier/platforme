# ═══ LA PREUVE QUE LA CHAINE A TOURNE ═══
#
# Appele par `commit-msg`, dernier hook avant que le commit existe.
# `post-commit` cherchera ce jeton : son absence signifie `--no-verify`, et le
# commit est alors defait.
#
# PAS PENDANT UNE FUSION. Git lance `post-merge` et NON `post-commit` sur un
# merge : personne ne consommerait le jeton, il resterait en place, et le
# prochain `git commit --no-verify` s'en servirait pour passer.
#
# Mesure faite : sans ce test, une seule fusion rouvrait le contournement.
#
# Extrait dans son propre fichier pour que le banc d'essai puisse l'exercer
# REELLEMENT, plutot qu'une copie qui divergerait sans prevenir.
repertoire_git=$(git rev-parse --git-dir)

if [ ! -f "$repertoire_git/MERGE_HEAD" ]; then
  date +%s >"$repertoire_git/harnais-valide"
fi
