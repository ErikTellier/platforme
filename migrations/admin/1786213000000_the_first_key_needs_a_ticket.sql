-- Up Migration

-- ON N'ENTRE PAS SANS TOUCHER SA CLÉ, ET ON NE PEUT PAS ENREGISTRER SA CLÉ
-- SANS ÊTRE ENTRÉ.
--
-- La connexion se fait en deux temps — Entra, puis le jeton matériel — et le
-- second est ce qui débloque l'émission d'une paire de jetons. Un administrateur
-- qui n'a encore aucun authentificateur ne peut donc jamais franchir la seconde
-- étape, et il n'existe aucun chemin pour en enregistrer un puisque ce chemin
-- serait derrière la seconde étape.
--
-- Le ticket est la sortie de ce cercle. Il autorise UN administrateur à
-- enregistrer UN authentificateur, pendant UN QUART D'HEURE.
--
--
-- ═══ IL NE REMPLACE PAS LA PRÉSENCE ═══
--
-- C'est le point à ne pas confondre. Le ticket permet de FABRIQUER une clé ;
-- il ne vaut pas preuve d'en détenir une. Après l'enrôlement, le parcours
-- normal reprend : défi, touche, présence vérifiée, paire émise. Personne
-- n'entre jamais sans avoir touché son jeton, pas même au premier passage.
--
--
-- ═══ QUINZE MINUTES, DONC UNE REMISE SYNCHRONE ═══
--
-- La durée exclut l'envoi par messagerie : le ticket serait périmé avant
-- d'être lu. Elle impose de l'émettre quand la personne est là — au téléphone,
-- en visioconférence — et c'est précisément l'intérêt : un ticket ne dort
-- jamais dans une boîte de réception.
--
-- Conséquence directe : il faut pouvoir réémettre, et souvent. Le déclencheur
-- annule le précédent, comme `session_supersede` clôt la session précédente ;
-- l'index partiel tient la garantie sous concurrence, comme `uq_session_mono`.
-- Ce sont les mêmes gestes parce que c'est le même problème.
--
--
-- ═══ UNE EMPREINTE, JAMAIS LE SECRET ═══
--
-- `login_flow` garde son `code_verifier` en clair, et c'est défendable : il vit
-- dix minutes et ne sert qu'à l'échange suivant. Un ticket ouvre le droit de
-- fabriquer une clé de signature — une copie de la base rendrait des tickets
-- utilisables par qui la lit.
--
-- On stocke donc le SHA-256 du secret, en base64url. Le secret naît chez celui
-- qui l'émet, transite par la voix, et n'existe nulle part ailleurs. Même
-- idiome que `cnf_jkt`, qui est « une empreinte, pas une clé ».
--
--
-- ═══ CE QUE LA TABLE NE DIT PAS ═══
--
-- Elle ne dit pas si l'administrateur a déjà un authentificateur. Le ticket
-- autorise l'enrôlement, pas le PREMIER enrôlement : remplacer une clé perdue
-- est le même besoin, et deux mécanismes pour un besoin finissent par diverger.
--
-- `issued_by` est nullable, et c'est le seul cas légitime : le tout premier
-- ticket n'a pas d'émetteur, comme le premier administrateur n'a pas de
-- créateur. Tous les autres en ont un.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD121  ticket refusé : l'administrateur est inactif ou inconnu
--
--   STANDARD codes, enforced by constraints:
--     23514  check_violation — fenêtre au-delà de quinze minutes, empreinte
--            de mauvaise forme, ou ticket à la fois dépensé et annulé
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE TABLE admin.enrollment_ticket (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES admin."user"(id) ON DELETE RESTRICT,
  secret_hash text NOT NULL,
  issued_by   uuid REFERENCES admin."user"(id) ON DELETE RESTRICT,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at  timestamptz,

  CONSTRAINT ticket_expiry_after_creation
    CHECK (expires_at > created_at),

  -- Le plafond dans le catalogue et pas seulement dans la fonction : la
  -- fonction empêche l'erreur d'appel, la contrainte ferme les autres chemins.
  CONSTRAINT ticket_window_bounded
    CHECK (expires_at <= created_at + interval '15 minutes'),

  -- SHA-256 en base64url sans remplissage.
  CONSTRAINT ticket_hash_shape
    CHECK (char_length(secret_hash) = 43),

  -- Dépensé ou annulé, jamais les deux : un ticket a une seule fin.
  CONSTRAINT ticket_single_end
    CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);

CREATE UNIQUE INDEX uq_ticket_live_per_user
  ON admin.enrollment_ticket (user_id)
  WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX ix_ticket_purgeable ON admin.enrollment_ticket (created_at);

COMMENT ON TABLE admin.enrollment_ticket IS
  'Le droit, pour un administrateur nommé, d''enregistrer un authentificateur pendant un quart d''heure. Il n''est pas une preuve de présence : il permet de fabriquer la clé, après quoi il faut s''en servir pour entrer.';
COMMENT ON COLUMN admin.enrollment_ticket.secret_hash IS
  'SHA-256 du secret, en base64url. Le secret lui-même n''est jamais écrit : il naît chez l''émetteur et se transmet de vive voix.';
COMMENT ON COLUMN admin.enrollment_ticket.issued_by IS
  'Qui l''a émis. NULL pour le tout premier, qui n''a pas d''émetteur — le pendant du premier administrateur, qui n''a pas de créateur.';
COMMENT ON COLUMN admin.enrollment_ticket.revoked_at IS
  'Remplacé par un ticket plus récent. Distinct de consumed_at : un ticket dépensé a servi, un ticket annulé n''a jamais servi, et l''audit doit pouvoir les distinguer.';
COMMENT ON INDEX admin.uq_ticket_live_per_user IS
  'Au plus un ticket vivant par administrateur, garanti par le moteur. Le déclencheur d''annulation est l''ergonomie ; cet index est l''invariant.';

-- ---------------------------------------------------------------------
-- Émettre annule le précédent, comme se reconnecter clôt la session.
-- ---------------------------------------------------------------------
CREATE FUNCTION admin.ticket_supersede() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  UPDATE admin.enrollment_ticket
     SET revoked_at = now()
   WHERE user_id = NEW.user_id
     AND consumed_at IS NULL
     AND revoked_at IS NULL
     AND id <> NEW.id;
  RETURN NEW;
END $$;

CREATE TRIGGER ticket_supersede
  BEFORE INSERT ON admin.enrollment_ticket
  FOR EACH ROW EXECUTE FUNCTION admin.ticket_supersede();

CREATE FUNCTION admin.ticket_emission_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM 1 FROM admin.active_user u WHERE u.id = NEW.user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket refused: admin % is inactive or unknown', NEW.user_id
      USING ERRCODE = 'AD121';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER ticket_emission_guard
  BEFORE INSERT ON admin.enrollment_ticket
  FOR EACH ROW EXECUTE FUNCTION admin.ticket_emission_guard();

-- ---------------------------------------------------------------------
-- Le chemin applicatif. La table reste innommable.
-- ---------------------------------------------------------------------
CREATE FUNCTION admin.issue_enrollment_ticket(
  p_user_id     uuid,
  p_secret_hash text,
  p_issued_by   uuid DEFAULT NULL
) RETURNS TABLE (id uuid, expires_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  INSERT INTO admin.enrollment_ticket (user_id, secret_hash, issued_by, expires_at)
  VALUES (p_user_id, p_secret_hash, p_issued_by, now() + interval '15 minutes')
  RETURNING enrollment_ticket.id, enrollment_ticket.expires_at;
$$;

COMMENT ON FUNCTION admin.issue_enrollment_ticket IS
  'Émet un ticket et annule celui qui vivait. La durée est ici et non chez l''appelant : un quart d''heure est une décision du plan, pas de celui qui appelle. L''appelant fournit une empreinte, jamais un secret.';

CREATE FUNCTION admin.consume_enrollment_ticket(
  p_user_id     uuid,
  p_secret_hash text
) RETURNS TABLE (id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  UPDATE admin.enrollment_ticket t
     SET consumed_at = now()
   WHERE t.user_id     = p_user_id
     AND t.secret_hash = p_secret_hash
     AND t.consumed_at IS NULL
     AND t.revoked_at  IS NULL
     AND now() < t.expires_at
  RETURNING t.id;
$$;

COMMENT ON FUNCTION admin.consume_enrollment_ticket IS
  'Dépense un ticket en un seul UPDATE. Zéro ligne signifie inconnu, déjà dépensé, annulé ou expiré — l''appelant refuse sans distinguer. La comparaison porte sur le couple (administrateur, empreinte) : présenter le ticket d''un autre ne sert à rien.';

CREATE FUNCTION admin.purge_enrollment_tickets()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_keep    interval;
  v_batch   integer;
  v_deleted integer;
BEGIN
  SELECT keep_for, batch_size INTO v_keep, v_batch
    FROM admin.retention WHERE relation = 'admin.enrollment_ticket';

  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  WITH doomed AS (
    SELECT t.id
      FROM admin.enrollment_ticket t
     WHERE t.created_at < now() - v_keep
       -- Un ticket vivant n'est jamais candidat : quelqu'un est peut-être en
       -- train de brancher sa clé.
       AND (t.consumed_at IS NOT NULL OR t.revoked_at IS NOT NULL
            OR t.expires_at < now())
     LIMIT v_batch
  )
  DELETE FROM admin.enrollment_ticket t USING doomed d WHERE t.id = d.id;

  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END $$;

INSERT INTO admin.retention (relation, keep_for) VALUES
  ('admin.enrollment_ticket', interval '7 days')
ON CONFLICT (relation) DO NOTHING;

-- ---------------------------------------------------------------------
-- L'observation, sans les empreintes.
-- ---------------------------------------------------------------------
CREATE VIEW api.enrollment_ticket AS
  SELECT id, user_id, issued_by, created_at, expires_at, consumed_at, revoked_at
    FROM admin.enrollment_ticket;

COMMENT ON VIEW api.enrollment_ticket IS
  'Les tickets, sans leur empreinte. De quoi savoir qui peut s''enrôler et jusqu''à quand, de quoi ne rien en faire d''autre.';

SELECT audit.watch('admin', 'enrollment_ticket',
                   '{user_id, issued_by, expires_at, consumed_at, revoked_at}');

REVOKE EXECUTE ON FUNCTION admin.issue_enrollment_ticket(uuid, text, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.consume_enrollment_ticket(uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.purge_enrollment_tickets() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION admin.issue_enrollment_ticket(uuid, text, uuid) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.consume_enrollment_ticket(uuid, text) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.purge_enrollment_tickets() TO app_admin_plane;

GRANT SELECT ON api.enrollment_ticket TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP VIEW api.enrollment_ticket;
DROP FUNCTION admin.purge_enrollment_tickets();
DROP FUNCTION admin.consume_enrollment_ticket(uuid, text);
DROP FUNCTION admin.issue_enrollment_ticket(uuid, text, uuid);
DROP TRIGGER ticket_emission_guard ON admin.enrollment_ticket;
DROP FUNCTION admin.ticket_emission_guard();
DROP TRIGGER ticket_supersede ON admin.enrollment_ticket;
DROP FUNCTION admin.ticket_supersede();
DROP TABLE admin.enrollment_ticket;

-- La ligne de politique reste : `no_delete_retention` l'interdit, et une ligne
-- retirée éteindrait une purge en silence.

RESET ROLE;
