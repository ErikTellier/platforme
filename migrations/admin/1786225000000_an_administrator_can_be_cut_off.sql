-- Up Migration

-- ON PEUT ENFIN COUPER QUELQU'UN.
--
-- `admin."user"` porte `deactivated_at` depuis le premier jour, `active_user` le
-- lit, `validate_bearer` joint cette vue, et AD001/AD003 refusent d'émettre quoi
-- que ce soit à un administrateur désactivé. Tout était prêt — sauf le geste.
-- AUCUNE requête du contrat ne touchait cette colonne : le seul utilisateur
-- désactivé de la base l'avait été par une migration.
--
-- Le plan savait donc rendre une compromission difficile, et pas la réparer.
--
--
-- ═══ DÉSACTIVER NE SUFFIT PAS, ET C'EST LE CŒUR DE CETTE MIGRATION ═══
--
-- Poser `deactivated_at` arrête le porteur à la seconde : `validate_bearer`
-- joint `active_user`, donc la prochaine requête est refusée. Mais la SESSION
-- resterait `ended_at IS NULL`, et c'est là que ça se gâte :
--
--   · `destroyable_key` ne rend une clé reprenable qu'une fois la session close.
--     La clé Ed25519 de l'administrateur révoqué survivrait donc dans le KMS
--     jusqu'au plafond d'une heure — du matériel privé vivant pour quelqu'un
--     qu'on vient précisément de mettre dehors ;
--   · `expire_sessions` finirait par la ranger sous EXPIRED, ce qui MENT sur la
--     cause. Une session coupée n'est pas une session oubliée, et le journal
--     d'incident se lit des mois plus tard.
--
-- Les deux gestes sont donc UN SEUL ACTE. C'est le même raisonnement que
-- `consume_enrollment_ticket` et l'inscription de la clé : ce qui n'a de sens
-- qu'ensemble s'écrit ensemble.
--
--
-- ═══ CE QU'ELLE NE FAIT PAS ═══
--
-- Elle ne révoque PAS les authentificateurs. Désactiver n'est pas forcément
-- soupçonner : un administrateur qui part n'a pas une clé compromise, et
-- `active_user` suffit déjà à ce que ses clés n'ouvrent plus rien. Soupçonner un
-- clone est un autre fait, il aura sa propre fonction et son propre motif.
--
-- Elle ne consigne PAS qui a coupé. La colonne n'existe pas, et l'inventer pour
-- y écrire ce que personne ne vérifie serait pire que rien — `audit.event`
-- retient déjà le rôle, la transaction et l'instant. Le jour où une autorité
-- signée portera ce geste, l'attribution viendra de la commande, pas d'un
-- paramètre qu'on veut bien renseigner.
--
--
-- ═══ LE DERNIER ADMINISTRATEUR PLATEFORME NE SE COUPE PAS ═══
--
-- Sans ce garde-fou, une seule commande suffirait à rendre le plan
-- définitivement inadministrable — et elle serait irréversible, `admin."user"`
-- étant append-only en suppression. AD004 ferme la porte.
--
-- C'est une protection contre l'ACCIDENT, pas contre l'adversaire : qui tient le
-- rôle de la base tient déjà bien davantage. Elle vaut pour ce qu'elle vaut, et
-- pour ce qu'elle annonce — le jour où le repli existera, c'est lui qui rouvrira
-- ce que celle-ci refuse.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   AD004  user: the last live platform admin may not be revoked
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- Un motif ne se supprime pas — la descente le DÉPRÉCIE — donc la remontée doit
-- savoir le retrouver déprécié et le relever, sans quoi un cycle down/up
-- buterait sur sa propre clé primaire.
INSERT INTO admin.session_end_reason (code, description) VALUES
  ('REVOKED', 'The administrator was deactivated; the session was cut with them.')
ON CONFLICT (code) DO UPDATE SET deprecated_at = NULL;

CREATE FUNCTION admin.revoke_admin(p_user_id uuid)
RETURNS TABLE (deactivated_at timestamptz, sessions_closed integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_when   timestamptz;
  v_closed integer;
BEGIN
  -- LE DERNIER DEBOUT NE TOMBE PAS. `effective_authority` sait déjà ce que
  -- « vivante » veut dire — ni révoquée, ni périmée, ni portée par un
  -- administrateur désactivé — donc on ne le redit pas ici : le jour où cette
  -- définition changera, elle changera à un seul endroit.
  IF EXISTS (
       SELECT 1 FROM admin.effective_authority e
        WHERE e.user_id = p_user_id AND e.scope = 'PLATFORM'
     )
     AND NOT EXISTS (
       SELECT 1 FROM admin.effective_authority e
        WHERE e.scope = 'PLATFORM' AND e.user_id <> p_user_id
     )
  THEN
    RAISE EXCEPTION 'AD004 the last live platform admin may not be revoked'
      USING ERRCODE = 'AD004';
  END IF;

  -- IDEMPOTENT. Une révocation déjà posée n'est pas redatée : c'est un fait, et
  -- la redater effacerait l'instant réel. On ne touche que ce qui est encore nul.
  UPDATE admin."user" u
     SET deactivated_at = now()
   WHERE u.id = p_user_id
     AND u.deactivated_at IS NULL;

  SELECT u.deactivated_at INTO v_when
    FROM admin."user" u WHERE u.id = p_user_id;

  IF v_when IS NULL THEN
    -- Ni désactivé, ni trouvé : l'administrateur n'existe pas. Zéro ligne, comme
    -- partout — l'appelant lit « rien à couper », pas une exception.
    RETURN;
  END IF;

  -- LA SESSION MEURT AVEC LUI, et c'est ce geste qui rend la clé reprenable.
  UPDATE admin.session s
     SET ended_at = now(), end_reason = 'REVOKED'
   WHERE s.user_id = p_user_id
     AND s.ended_at IS NULL;

  GET DIAGNOSTICS v_closed = ROW_COUNT;

  RETURN QUERY SELECT v_when, v_closed;
END $$;

COMMENT ON FUNCTION admin.revoke_admin IS
'Coupe un administrateur : pose deactivated_at et ferme ses sessions vivantes
sous REVOKED, dans le même acte.

Les deux ensemble, jamais l''un sans l''autre. Désactiver seul arrêterait le
porteur — validate_bearer joint active_user — mais laisserait la session ouverte,
donc sa clé privée vivante dans le KMS jusqu''au plafond d''une heure, et la
session finirait rangée sous EXPIRED, ce qui ment sur la cause.

Idempotente : une révocation déjà posée n''est pas redatée. Zéro ligne si
l''administrateur n''existe pas. AD004 si c''est la dernière autorité PLATEFORME
encore vivante — le plan deviendrait inadministrable, sans retour possible.

Ne révoque pas les authentificateurs : partir n''est pas être soupçonné.';

REVOKE EXECUTE ON FUNCTION admin.revoke_admin(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.revoke_admin(uuid) TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP FUNCTION admin.revoke_admin(uuid);

-- LE MOTIF N'EST PAS SUPPRIMÉ, IL EST DÉPRÉCIÉ. `no_delete_end_reason` refuserait
-- la suppression (AD040), et il a raison : des sessions closes le référencent
-- déjà, et redescendre une migration ne doit pas réécrire l'histoire de ce qui
-- s'est passé. `deprecated_at` dit exactement ce qu'on veut — plus personne ne
-- s'en sert désormais, ce qui l'a porté le garde (AD060).
UPDATE admin.session_end_reason SET deprecated_at = now()
 WHERE code = 'REVOKED' AND deprecated_at IS NULL;

RESET ROLE;
