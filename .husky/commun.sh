# ═══════════════════════════════════════════════════════════════════════════
#  SOCLE COMMUN DES HOOKS — source par chacun d'eux, en premiere ligne.
#
#  POURQUOI CE FICHIER EXISTE
#
#  Un hook ne tourne pas dans votre terminal. VS Code, JetBrains ou GitHub
#  Desktop lancent git dans un shell qui NE CHARGE PAS votre profil : fnm n'y
#  est pas actif, `node` est celui du systeme, et pnpm refuse de demarrer parce
#  que `engines` exige ^24.20.0.
#
#  Sans ce fichier, le harnais echoue depuis tout client graphique — et un
#  harnais qui echoue est un harnais qu'on finit par contourner.
# ═══════════════════════════════════════════════════════════════════════════

# Les hooks git tournent toujours a la racine de la copie de travail.
if command -v fnm >/dev/null 2>&1; then
  eval "$(fnm env --shell bash)" 2>/dev/null || true
  fnm use --install-if-missing >/dev/null 2>&1 || true
fi

# Verification explicite : mieux vaut un message qui nomme la cause qu'une
# erreur de pnpm trois etapes plus loin.
version_attendue=$(tr -d ' \t\r\n' <.nvmrc 2>/dev/null || echo '')
version_courante=$(node -v 2>/dev/null | tr -d 'v')

if [ -n "$version_attendue" ] && [ "${version_courante%%.*}" != "${version_attendue%%.*}" ]; then
  echo "" >&2
  echo "REFUS : mauvaise version de Node pour ce depot." >&2
  echo "" >&2
  echo "    attendu (.nvmrc) : $version_attendue" >&2
  echo "    obtenu           : ${version_courante:-aucun node trouve}" >&2
  echo "" >&2
  echo "  fnm n'a pas pu etre active depuis ce client git." >&2
  echo "  Depuis un terminal :  fnm use" >&2
  echo "" >&2
  exit 1
fi
