-- Up Migration

-- UNE CLÉ PERDUE SE REPREND, SANS QUOI ELLE FERME LA PORTE POUR TOUJOURS.
--
-- Le plan sait révoquer une accréditation dans un seul cas : `disarm_clone`,
-- quand `sign_count_guard` a levé AD031. C'est-à-dire quand un CLONE s'est
-- manifesté. Une clé simplement perdue, oubliée dans un train, ou remplacée par
-- un modèle plus récent, ne déclenche rien du tout — et reste vivante.
--
-- Or `refuseCleFantome` interdit d'en enrôler une seconde tant qu'une vivante
-- existe, et c'est une bonne règle : sans elle, un mot de passe hameçonné et un
-- ticket suffiraient à greffer une clé fantôme. Mais elle a une conséquence que
-- je n'avais pas fermée : PERDRE SA SEULE CLÉ VERROUILLE DÉFINITIVEMENT
-- L'ADMINISTRATEUR. Il ne peut pas entrer — il n'a plus de clé — et il ne peut
-- pas en enrôler une — il en a encore une, du point de vue de la base.
--
-- Cette fonction rompt ce blocage, et elle est le seul geste qui le puisse.
--
--
-- ═══ POURQUOI ELLE NE FERME PAS LES SESSIONS ═══
--
-- `disarm_clone` les ferme, et il le faut : une régression de compteur est la
-- preuve qu'un second exemplaire du secret SIGNE EN CE MOMENT. C'est une
-- intrusion en cours, et laisser la session ouverte serait laisser entrer par la
-- porte qu'on vient de condamner.
--
-- Une clé perdue n'est pas ça. Rien ne prouve que quelqu'un la détient, et si
-- quelqu'un la détient il lui faut encore passer Entra. L'administrateur qui
-- travaille dans une session prouvée n'a aucune raison d'être mis dehors parce
-- qu'il a égaré un objet chez lui.
--
-- Si la clé a été VOLÉE plutôt que perdue, c'est un second fait, et il a sa
-- propre commande : `revoke admin` coupe l'administrateur et ses sessions. Deux
-- faits distincts, deux gestes distincts — c'est la même raison qui fait que
-- `revoke_admin` ne touche pas aux clés.
--
--
-- ═══ CE QU'ELLE NE PROTÈGE PAS, ET C'EST VOULU ═══
--
-- Rien n'empêche de révoquer la DERNIÈRE clé d'un administrateur. Ce serait
-- même absurde de l'interdire : c'est le cas normal, celui de la clé unique
-- qu'on vient de perdre. L'administrateur devient temporairement sans clé, ce
-- qui est exactement l'état que le ticket d'enrôlement existe pour rattraper.
--
-- La commande le dit à voix haute plutôt que de le refuser.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Révoquer deux fois ne lève rien : la seconde fois rend
--   zéro ligne. Ressusciter une révocation lève AD032, posé par
--   `revocation_is_final` à la migration précédente.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE FUNCTION webauthn.revoke_authenticator(p_authenticator_id uuid)
RETURNS TABLE (user_id uuid, label text, was_last boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_user  uuid;
  v_label text;
BEGIN
  UPDATE webauthn.authenticator a
     SET revoked_at = now()
   WHERE a.id = p_authenticator_id
     AND a.revoked_at IS NULL
  RETURNING a.user_id, a.label INTO v_user, v_label;

  IF v_user IS NULL THEN
    -- Inconnue ou déjà révoquée. Zéro ligne : reprendre une clé qu'on a déjà
    -- reprise n'est pas une faute, et une commande de secours doit pouvoir
    -- être rejouée sans qu'on se demande si elle a marché.
    RETURN;
  END IF;

  -- `was_last` est une CONSTATATION, pas une garde. L'appelant a besoin de
  -- savoir qu'il vient de laisser quelqu'un sans clé — pour lui émettre un
  -- ticket — mais ce n'est pas à la base de le lui interdire : la clé unique
  -- qu'on vient de perdre est précisément le cas normal.
  RETURN QUERY
    SELECT v_user, v_label,
           NOT EXISTS (SELECT 1 FROM webauthn.authenticator a
                        WHERE a.user_id = v_user AND a.revoked_at IS NULL);
END $$;

COMMENT ON FUNCTION webauthn.revoke_authenticator IS
'Reprend une accréditation — perdue, remplacée, ou dont on ne veut plus. Rend son
administrateur, son libellé, et si c''était la dernière encore vivante.

Elle ne ferme AUCUNE session, contrairement à disarm_clone : une régression de
compteur prouve qu''un clone signe en ce moment, une clé égarée ne prouve rien.
Si la clé a été volée, revoke_admin est le second geste, et il coupe.

Elle ne refuse pas de reprendre la dernière : c''est le cas normal de la clé
unique perdue, et l''administrateur se rattrape par un ticket d''enrôlement.
Sans elle, refuseCleFantome le verrouillerait pour toujours — plus de clé pour
entrer, et une clé de trop pour en enrôler une.

Zéro ligne si l''accréditation est inconnue ou déjà reprise : une commande de
secours doit pouvoir être rejouée.';

REVOKE EXECUTE ON FUNCTION webauthn.revoke_authenticator(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION webauthn.revoke_authenticator(uuid) TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP FUNCTION webauthn.revoke_authenticator(uuid);

RESET ROLE;
