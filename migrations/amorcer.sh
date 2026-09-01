# ═══════════════════════════════════════════════════════════════════════════
#  AMORÇAGE DES BASES — une par service, deduite de l'arborescence.
#
#  UN DOSSIER DANS migrations/ = UNE BASE. C'est la seule liste de services du
#  depot ; il n'y en a pas de seconde a tenir a jour. Ajouter `facturation`,
#  c'est creer `migrations/facturation/` et relancer `docker compose up`.
#
#  Joue a CHAQUE demarrage, et non par /docker-entrypoint-initdb.d/ : ce
#  dernier ne s'execute qu'a la toute premiere initialisation du volume. Un
#  service ajoute plus tard n'aurait jamais sa base, et il faudrait un
#  `down -v` pour s'en apercevoir.
#
#  Tout est idempotent.
# ═══════════════════════════════════════════════════════════════════════════

set -eu

psqlc() { psql -v ON_ERROR_STOP=1 -q "$@"; }

for chemin in /migrations/*/; do
  base=$(basename "$chemin")

  # Les dossiers a underscore ne sont pas des services : `_amorcage` porte les
  # scripts joues ci-dessous.
  case "$base" in _*) continue ;; esac

  echo "── $base"

  # ─── LA BASE ─────────────────────────────────────────────────────────────
  #
  # Postgres n'a pas de CREATE DATABASE IF NOT EXISTS, et l'instruction ne
  # supporte pas d'etre dans un bloc. `\gexec` execute le texte rendu par la
  # requete — zero ligne quand la base existe deja.
  psqlc -d postgres -tAc \
    "SELECT format('CREATE DATABASE %I', '$base')
       WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$base')" | psqlc -d postgres

  # ─── LES DEUX ROLES PERMANENTS ───────────────────────────────────────────
  #
  # Un GROUPE de migration stable, dont chaque compte jetable fabrique par
  # OpenBao devient membre. Il porte les privileges de base ; le droit de
  # posseder les objets lui est ajoute par la migration, une fois que
  # `<base>_owner` existe.
  #
  # Les roles sont a l'echelle du SERVEUR, pas de la base : on les cree une
  # fois, depuis n'importe ou.
  psqlc -d postgres -c "DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${base}_migrator') THEN
        CREATE ROLE ${base}_migrator NOLOGIN;
      END IF;
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${base}_owner') THEN
        CREATE ROLE ${base}_owner NOLOGIN;
      END IF;
    END \$\$;"

  # LES TROIS OPTIONS, et pas seulement ADMIN. Depuis PostgreSQL 16, le
  # createur d'un role n'en recoit que l'administration : il peut le commenter,
  # pas l'endosser. Sans SET, la migration qui reattribue la propriete echoue
  # sur « must be able to SET ROLE ».
  psqlc -d postgres -c \
    "GRANT \"${base}_owner\" TO \"${base}_migrator\" WITH ADMIN TRUE, INHERIT TRUE, SET TRUE;"

  # ─── LES DROITS, EUX, SONT PROPRES A LA BASE ─────────────────────────────
  #
  # Depuis PostgreSQL 15, `public` n'accorde plus CREATE a PUBLIC : sans ces
  # GRANT, la table de suivi des migrations n'a nulle part ou se poser.
  psqlc -d "$base" -c "GRANT CREATE ON DATABASE \"$base\" TO \"${base}_migrator\";"
  psqlc -d "$base" -c "GRANT USAGE, CREATE ON SCHEMA public TO \"${base}_migrator\";"

  # Le proprietaire aussi : transferer un objet exige que son NOUVEAU
  # proprietaire ait le droit de creer dans le schema qui l'accueille.
  psqlc -d "$base" -c "GRANT USAGE, CREATE ON SCHEMA public TO \"${base}_owner\";"

  # ─── CE QUI EST PROPRE AU SERVICE ────────────────────────────────────────
  #
  # Extensions et roles applicatifs : voir migrations/_amorcage/<base>.sql pour
  # le motif de chacun. Absent = le service n'en a pas besoin.
  if [ -f "/migrations/_amorcage/$base.sql" ]; then
    psqlc -d "$base" -f "/migrations/_amorcage/$base.sql"
  fi
done

echo "amorcage termine"
