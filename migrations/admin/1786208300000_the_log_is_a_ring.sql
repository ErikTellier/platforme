-- Up Migration

-- LE JOURNAL POUSSAIT VERS L'AVANT ET N'OUBLIAIT JAMAIS.
--
-- `audit.ensure_partitions()` crée les mois manquants jusqu'à douze mois en
-- avant. Rien, nulle part, n'a jamais retiré un mois passé — ni dans les
-- migrations, ni dans les scripts. Le contrat le portait comme une obligation
-- de l'exploitant : « decide a retention period and detach old partitions ».
-- Une obligation écrite dans un contrat n'est pas un mécanisme.
--
-- L'anneau se referme ici : `ensure_partitions()` ouvre devant,
-- `detach_expired()` ferme derrière. Vingt-quatre mois attachés, ce que NIS2
-- pousse sur les traces d'administration.
--
--
-- ═══ DÉTACHER N'EST PAS SUPPRIMER, ET C'EST TOUT LE SUJET ═══
--
-- `DETACH PARTITION` sort la table du parent. Les lignes existent encore, dans
-- une table autonome du schéma `audit` : on peut les lire, les exporter, les
-- rattacher. `DROP` les détruit.
--
-- Pour un journal d'audit c'est la différence entre « archivé selon notre
-- politique » et « effacé », et c'est la deuxième question qu'un auditeur
-- pose. Cette fonction ne supprime donc RIEN, jamais. Elle détache, elle dit
-- ce qu'elle a détaché, et la suite — export, archivage, puis suppression —
-- appartient à qui a décidé de la politique.
--
-- `audit.awaiting_export` est la liste de travail de cette suite.
--
--
-- ═══ LE VERROU, ASSUMÉ ═══
--
-- `DETACH PARTITION` prend un ACCESS EXCLUSIVE bref sur le parent.
-- `CONCURRENTLY` l'éviterait mais ne s'exécute pas dans un bloc de
-- transaction, donc pas depuis une fonction. Pour une opération mensuelle,
-- quelques millisecondes de verrou sont le bon échange — et le dire vaut mieux
-- que de le découvrir.
--
--
-- ═══ LA PARTITION PAR DÉFAUT EST UNE FUITE, PAS UN FILET ═══
--
-- `event_overflow` absorbe ce qui n'appartient à aucun mois provisionné. Ces
-- lignes ne sont dans aucune partition datée : elles échappent à l'anneau et
-- grossissent indéfiniment. Une partition par défaut NON VIDE ne veut pas dire
-- « le filet a marché », elle veut dire « `ensure_partitions()` n'a pas tourné
-- à temps ». `audit.unpartitioned` la compte pour que ce soit un chiffre et
-- non une supposition.
--
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by functions (custom SQLSTATE):
--     XA020  no retention window is declared for the audit log
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- UNE LIGNE PAR RELATION PARTITIONNÉE, comme `admin.retention` en porte une
-- par relation purgeable. La première version portait un booléen `only_one`
-- avec une contrainte pour n'admettre qu'une ligne — la doctrine l'a refusé, et
-- elle avait raison : c'était un drapeau là où une clé suffit. La clé primaire
-- interdit deux fenêtres pour la même relation, ce qui était tout ce qu'on
-- voulait.
CREATE TABLE audit.retention (
    relation   text        NOT NULL,
    keep_for   interval    NOT NULL,
    -- Combien de mois au plus par appel. Détacher trente-six partitions d'un
    -- coup après un an sans exploitation tiendrait le verrou bien plus
    -- longtemps qu'un mois de rattrapage ne le mérite.
    per_call   int         NOT NULL DEFAULT 3,
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT retention_pk PRIMARY KEY (relation),
    CONSTRAINT retention_window_positive CHECK (keep_for > interval '0'),
    CONSTRAINT retention_per_call_positive CHECK (per_call > 0)
);

-- ON NE SUPPRIME PAS UNE POLITIQUE, on change sa fenêtre. Une ligne effacée
-- désactive la rétention EN SILENCE, ce qui est le seul échec qu'on ne voit
-- jamais venir : le journal continue de fonctionner, il ne s'arrête simplement
-- plus jamais de grossir.
CREATE TRIGGER retention_no_delete BEFORE DELETE ON audit.retention
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_write();

COMMENT ON TABLE audit.retention IS
'Combien de temps le journal reste ATTACHÉ. Dans le schéma `audit` et non dans
une table de politique de la base hôte : le schéma d''audit se réplique tel
quel dans les dix bases, et une fenêtre qui vivrait ailleurs manquerait à sept
d''entre elles.

Ce n''est pas une durée de conservation légale — c''est la durée pendant
laquelle le journal reste interrogeable en ligne. Ce qui est détaché existe
toujours.';

COMMENT ON COLUMN audit.retention.keep_for IS
'Vingt-quatre mois par défaut : ce que NIS2 pousse sur les traces
d''administration. Une ligne de table, donc un grand compte qui impose la
sienne par contrat la repose sans migration.';

INSERT INTO audit.retention (relation, keep_for)
VALUES ('audit.event', interval '24 months');


CREATE VIEW audit.partition_estate AS
SELECT c.relname                                     AS partition,
       -- LE NOM EST LE MOIS. On le lit plutôt que d'analyser le texte de
       -- `relpartbound` : ce texte est une représentation interne, sa forme
       -- change entre versions de Postgres, et une vue qui la décode se casse
       -- à une montée de version sans que rien ne l'annonce.
       to_date(right(c.relname, 6), 'YYYYMM')        AS covers_from,
       (to_date(right(c.relname, 6), 'YYYYMM')
          + interval '1 month')::date                AS covers_to,
       c.relispartition                              AS attached,
       -- ESTIMATION, et c'est voulu : une vue qui compterait vraiment ferait
       -- un parcours complet du journal à chaque ouverture de l'écran.
       c.reltuples::bigint                           AS rows_estimate,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS size
  FROM pg_class AS c
  INNER JOIN pg_namespace AS n ON c.relnamespace = n.oid
 WHERE n.nspname = 'audit'
   AND c.relkind = 'r'
   AND c.relname ~ '^event_[0-9]{6}$';

COMMENT ON VIEW audit.partition_estate IS
'Tous les mois du journal, attachés ou non, avec leurs bornes et leur taille.
La seule lecture qui répond à « depuis quand pouvez-vous interroger vos
traces » sans ouvrir un shell.';


CREATE VIEW audit.awaiting_export AS
SELECT partition, covers_from, covers_to, rows_estimate, size
  FROM audit.partition_estate
 WHERE NOT attached;

COMMENT ON VIEW audit.awaiting_export IS
'Ce qui est sorti de l''anneau et attend son archivage. La liste de travail de
l''export : détacher est le signal, exporter puis supprimer appartient à qui a
décidé de la politique. Tant qu''une ligne figure ici, rien n''a été perdu.';


CREATE VIEW audit.unpartitioned AS
SELECT count(*) AS rows,
       min(occurred_at) AS oldest,
       max(occurred_at) AS newest
  FROM audit.event_overflow;

COMMENT ON VIEW audit.unpartitioned IS
'Les événements tombés dans la partition par défaut. Un compte non nul n''est
pas un filet qui a fonctionné : c''est `ensure_partitions()` qui n''a pas tourné
à temps, et ces lignes échappent à l''anneau — jamais détachées, donc jamais
archivées, donc éternelles.

ET C''EST PIRE QUE DU DÉSORDRE : une partition par défaut qui contient des
lignes d''un mois EMPÊCHE de provisionner ce mois-là. Postgres refuse —
« updated partition constraint for default partition would be violated by some
row ». Il faut sortir les lignes avant de pouvoir créer la partition, donc
avant de pouvoir un jour l''archiver. Mesuré, pas supposé.';


CREATE FUNCTION audit.detach_expired()
RETURNS TABLE (partition text, covers_from date, covers_to date, rows bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_keep   interval;
    v_limit  int;
    v_cut    date;
    r        record;
    n        bigint;
    done     int := 0;
BEGIN
    SELECT keep_for, per_call INTO v_keep, v_limit
      FROM audit.retention WHERE relation = 'audit.event';

    -- FERMÉ ET BRUYANT. `purge_challenges` rend zéro quand aucune politique
    -- n'est déclarée, et c'est juste pour des défis éphémères. Ici le silence
    -- signifierait « la rétention ne tourne plus » sans que personne ne
    -- l'apprenne — exactement ce qu'un audit qui échoue en silence a de pire.
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no retention window is declared for the audit log'
            USING ERRCODE = 'XA020',
                  HINT = 'audit.retention holds exactly one row. Without it '
                         'nothing is ever detached, and the log outgrows the '
                         'data it protects.';
    END IF;

    v_cut := (date_trunc('month', now()) - v_keep)::date;

    FOR r IN
        SELECT p.partition, p.covers_from, p.covers_to
          FROM audit.partition_estate p
         WHERE p.attached AND p.covers_to <= v_cut
         ORDER BY p.covers_from
    LOOP
        EXIT WHEN done >= v_limit;

        EXECUTE format('SELECT count(*) FROM audit.%I', r.partition) INTO n;
        EXECUTE format('ALTER TABLE audit.event DETACH PARTITION audit.%I',
                       r.partition);

        partition   := r.partition;
        covers_from := r.covers_from;
        covers_to   := r.covers_to;
        rows        := n;
        done        := done + 1;
        RETURN NEXT;
    END LOOP;
END;
$$;

REVOKE EXECUTE ON FUNCTION audit.detach_expired() FROM PUBLIC;

COMMENT ON FUNCTION audit.detach_expired() IS
'Ferme l''anneau : détache les mois sortis de la fenêtre, et rend ce qu''elle a
détaché — nom, bornes, nombre exact de lignes. De quoi écrire un manifeste
d''export sans relire la base.

ELLE NE SUPPRIME RIEN. Détacher est le signal ; exporter, archiver puis
supprimer appartient à qui a décidé de la politique. Un journal qu''une
fonction de maintenance peut effacer n''est pas un journal.

Le compte est EXACT ici, contrairement à `partition_estate` : c''est un appel
mensuel sur une table qu''on s''apprête à sortir, et un manifeste d''archivage
approximatif ne vaut rien.

S''exécute sous le propriétaire du schéma — c''est du DDL. `ALTER TABLE ...
DETACH` prend un ACCESS EXCLUSIVE bref sur le parent ; `CONCURRENTLY`
l''éviterait mais ne s''exécute pas dans une transaction, donc pas depuis une
fonction.';

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP FUNCTION audit.detach_expired();
DROP VIEW audit.unpartitioned;
DROP VIEW audit.awaiting_export;
DROP VIEW audit.partition_estate;
DROP TRIGGER retention_no_delete ON audit.retention;
DROP TABLE audit.retention;

RESET ROLE;
