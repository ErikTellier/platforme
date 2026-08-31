-- Up Migration

-- UN CLONE SOUPÇONNÉ EST DÉSARMÉ, PAS SEULEMENT SIGNALÉ.
--
-- `sign_count_guard` lève AD031 quand le compteur d'un authentificateur ne
-- progresse pas strictement. C'est le seul signal que la norme WebAuthn offre
-- contre la duplication d'une clé : deux exemplaires du même secret comptent
-- chacun de leur côté, et l'un des deux finit par présenter un nombre que
-- l'autre a déjà dépassé.
--
-- Le plan le détectait déjà — et n'en faisait RIEN. `loginFinish` et
-- `presenceFinish` rendaient 409, journalisaient, et la vie continuait : session
-- ouverte, accréditation vivante, clé toujours acceptée au prochain essai.
-- Détecter une clé clonée et la laisser en place est la même faute que la clé
-- qui survivait à sa session, prise par l'autre bout.
--
--
-- ═══ POURQUOI RÉVOQUER PLUTÔT QUE SUSPENDRE ═══
--
-- Il n'existe pas d'état « douteux ». Une régression de compteur signifie qu'un
-- second exemplaire du secret a signé — soit qu'on l'a copié, soit que le
-- fabricant a mal fait son travail. On ne peut pas savoir lequel des deux
-- exemplaires est celui du légitime, DONC ON N'EN GARDE AUCUN. L'administrateur
-- réenrôle avec un ticket ; c'est un dérangement, et c'est le bon prix.
--
-- Faux positif possible : certaines clés remettent leur compteur à zéro après
-- une réinitialisation, et quelques modèles ne comptent pas du tout. Le coût de
-- se tromper est un réenrôlement ; le coût de ne pas agir est un accès
-- permanent à qui a copié la clé. Le choix n'est pas serré.
--
--
-- ═══ ET LA SESSION MEURT AVEC ═══
--
-- Révoquer l'accréditation sans fermer la session laisserait entrer par la porte
-- qu'on vient de condamner : le porteur en cours ne relit pas les
-- authentificateurs, il ne connaît que sa paire. La session tombe donc aussi, et
-- sous son propre motif — CLONED, et non SECURITY, qui nomme le rejeu de
-- refresh. Un journal d'incident se lit des mois plus tard, et « clone soupçonné
-- sur telle accréditation » n'est pas « quelqu'un a rejoué un jeton ».
--
--
-- ═══ UNE RÉVOCATION EST UN FAIT ═══
--
-- `revoked_at` n'avait aucun garde : rien n'empêchait de le remettre à NULL et
-- de ressusciter une accréditation condamnée. C'est exactement ce qu'AD021
-- interdit déjà pour les clés — « irreversible fact re-posted ». AD032 le dit
-- pour les authentificateurs.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   AD032  webauthn: a revocation is a fact; it is never lifted
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

INSERT INTO admin.session_end_reason (code, description) VALUES
  ('CLONED', 'Authenticator counter regression: a duplicate of the key is suspected.')
ON CONFLICT (code) DO UPDATE SET deprecated_at = NULL;

CREATE FUNCTION webauthn.revocation_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'AD032 a revocation is a fact; it is never lifted'
      USING ERRCODE = 'AD032';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER revocation_is_final
  BEFORE UPDATE OF revoked_at ON webauthn.authenticator
  FOR EACH ROW EXECUTE FUNCTION webauthn.revocation_is_final();

CREATE FUNCTION webauthn.disarm_clone(
  p_user_id       uuid,
  p_credential_id bytea
) RETURNS TABLE (authenticator_id uuid, sessions_closed integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_id     uuid;
  v_closed integer;
BEGIN
  UPDATE webauthn.authenticator a
     SET revoked_at = now()
   WHERE a.credential_id = p_credential_id
     AND a.user_id       = p_user_id
     AND a.revoked_at IS NULL
  RETURNING a.id INTO v_id;

  IF v_id IS NULL THEN
    -- Inconnue, d'un autre administrateur, ou déjà désarmée. Zéro ligne :
    -- l'appelant n'a rien à réparer, et un second passage ne doit pas se
    -- plaindre — le chemin qui mène ici est justement un chemin d'incident,
    -- où l'on peut repasser deux fois.
    RETURN;
  END IF;

  -- La session tombe avec l'accréditation : le porteur en cours ne relit jamais
  -- les authentificateurs, il ne connaît que sa paire.
  UPDATE admin.session s
     SET ended_at = now(), end_reason = 'CLONED'
   WHERE s.user_id = p_user_id
     AND s.ended_at IS NULL;

  GET DIAGNOSTICS v_closed = ROW_COUNT;

  RETURN QUERY SELECT v_id, v_closed;
END $$;

COMMENT ON FUNCTION webauthn.disarm_clone IS
'Désarme une accréditation dont le compteur a régressé : la révoque et ferme les
sessions vivantes de son administrateur sous CLONED, dans le même acte.

Appelée quand sign_count_guard a levé AD031. Les deux gestes ensemble : révoquer
sans fermer laisserait entrer par la porte qu''on vient de condamner, puisqu''un
porteur en cours ne relit pas les authentificateurs.

Il n''existe pas d''état « douteux ». Une régression signifie qu''un second
exemplaire du secret a signé, et rien ne dit lequel est celui du légitime — on
n''en garde donc aucun, et l''administrateur réenrôle avec un ticket.

Zéro ligne si l''accréditation est inconnue, d''un autre administrateur, ou déjà
désarmée : ce chemin est un chemin d''incident, on peut y repasser.';

REVOKE EXECUTE ON FUNCTION webauthn.disarm_clone(uuid, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION webauthn.disarm_clone(uuid, bytea) TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP FUNCTION webauthn.disarm_clone(uuid, bytea);
DROP TRIGGER revocation_is_final ON webauthn.authenticator;
DROP FUNCTION webauthn.revocation_is_final();

UPDATE admin.session_end_reason SET deprecated_at = now()
 WHERE code = 'CLONED' AND deprecated_at IS NULL;

RESET ROLE;
