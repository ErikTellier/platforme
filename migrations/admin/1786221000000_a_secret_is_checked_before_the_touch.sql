-- Up Migration

-- UNE FAUTE DE FRAPPE NE DOIT PAS COÛTER UNE TOUCHE.
--
-- L'enrôlement se joue en deux temps : `begin` rend de quoi appeler la clé,
-- `finish` vérifie l'attestation et dépense le ticket. Le secret n'était présenté
-- qu'au second temps — donc un secret mal entendu au téléphone se découvrait
-- APRÈS que l'administrateur ait touché sa clé, et le défi étant consommé, il
-- fallait tout recommencer.
--
-- Le contrôle remonte donc au premier temps. C'est la même règle que
-- `is_live_ticket` applique déjà pour l'existence : refuser tôt ce qu'on refusera
-- de toute façon, pour ne pas faire agir quelqu'un pour rien.
--
--
-- ═══ POURQUOI UNE FONCTION ET PAS UNE COLONNE DE PLUS ═══
--
-- `api.enrollment_ticket` publie « les tickets, sans leur empreinte : de quoi
-- savoir qui peut s'enrôler et jusqu'à quand, de quoi ne rien en faire d'autre ».
-- Y ajouter `secret_hash` pour permettre la comparaison retirerait exactement ce
-- que cette phrase garantit.
--
-- Une fonction répond à la QUESTION — « ce secret ouvre-t-il un ticket » — sans
-- publier de quoi la poser autrement. Le plan apprend oui ou non, jamais
-- l'empreinte, et il ne peut donc pas la comparer hors ligne à autre chose.
--
--
-- ═══ CE QU'ELLE NE FAIT PAS ═══
--
-- Elle ne consomme rien. C'est `consume_enrollment_ticket` qui dépense, au
-- moment où la clé existe et dans la même transaction que son inscription. Entre
-- les deux, le ticket reste ouvert : une touche refusée par l'utilisateur, une
-- fenêtre fermée, un navigateur qui plante ne coûtent rien.
--
-- Deux appels successifs peuvent donc voir le même ticket. C'est voulu — ce n'est
-- pas une réservation, c'est une question.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code. La fonction rend un booléen, jamais une exception : un secret
--   qui n'ouvre rien n'est pas une panne.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE FUNCTION admin.ticket_is_open(
  p_user_id     uuid,
  p_secret_hash text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (
    SELECT 1
      FROM admin.enrollment_ticket t
     WHERE t.user_id     = p_user_id
       AND t.secret_hash = p_secret_hash
       AND t.consumed_at IS NULL
       AND t.revoked_at  IS NULL
       AND now() < t.expires_at
  );
$$;

COMMENT ON FUNCTION admin.ticket_is_open IS
'Ce secret ouvre-t-il un ticket vivant pour cet administrateur ? Rend oui ou non,
et rien d''autre — l''empreinte reste inaccessible, comme dans api.enrollment_ticket.

Sert à refuser AVANT la touche : découvrir un secret mal entendu après que
quelqu''un a présenté sa clé lui fait tout recommencer pour rien. Ne consomme
pas : c''est consume_enrollment_ticket qui dépense, quand la clé existe.';

REVOKE EXECUTE ON FUNCTION admin.ticket_is_open(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.ticket_is_open(uuid, text) TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP FUNCTION admin.ticket_is_open(uuid, text);

RESET ROLE;
