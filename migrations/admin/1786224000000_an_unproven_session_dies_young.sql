-- Up Migration

-- UNE SESSION QUI N'A PAS PROUVÉ SA PRÉSENCE NE MÉRITE PAS UNE HEURE.
--
-- Depuis que la connexion se fait en deux temps, il existe un état qui n'existait
-- pas quand cette fonction a été écrite : une session VIVANTE ET SANS PAIRE.
-- Entra a répondu, la session est ouverte, sa clé est frappée — et la clé
-- matérielle n'a pas encore été touchée.
--
-- `expire_sessions` datait la mort au plus tôt de deux bornes : le plafond d'une
-- heure, et l'inactivité de la paire non remplacée. Sans paire, la seconde borne
-- est NULL, et LEAST l'ignore — il ne reste que le plafond. Une session
-- abandonnée entre Entra et la clé vivait donc UNE HEURE, là où une session
-- normale meurt après quinze minutes d'inactivité. L'état le moins prouvé était
-- devenu le plus durable, ce qui est exactement l'inverse de ce qu'on veut.
--
--
-- ═══ CE QUI VIT VRAIMENT PENDANT CE TEMPS ═══
--
-- La session n'est pas le sujet. Le sujet est SA CLÉ : `open_session` frappe une
-- Ed25519 dans le KMS avant même d'ouvrir la transaction, et `destroyable_key` ne
-- la rend reprenable qu'une fois la session close. Une heure de session
-- abandonnée, c'est une heure de matériel privé vivant pour une connexion que
-- personne n'a fini de faire — « elle est dangereuse par définition ».
--
-- Le laissez-passer, lui, meurt à cinq minutes. Passé ce délai la session est
-- déjà inerte : plus rien ne peut l'emprunter, ni pour entrer ni pour agir. Ce
-- que cette migration ajoute ne retire donc AUCUNE capacité — elle aligne
-- simplement la mort de la session sur la mort de ce qui pouvait s'en servir.
--
--
-- ═══ POURQUOI UN PARAMÈTRE PLUTÔT QU'UNE CONSTANTE ═══
--
-- Le même geste que `rotate_pair(p_inactivity interval DEFAULT '15 minutes')` :
-- le délai est déclaré ici, une fois, et l'appelant peut le nommer s'il a une
-- raison. Le plan Go garde `pendingLifetime` de son côté pour SIGNER le
-- laissez-passer ; les deux doivent rester égaux, et c'est ici que la valeur fait
-- foi — un plan qui signerait plus long ne ferait qu'émettre des jetons pour des
-- sessions que la base a déjà déclarées mortes.
--
-- ATTENTION AU REMPLACEMENT : ajouter un paramètre à défaut ne remplace pas la
-- fonction, il la SURCHARGE, et `expire_sessions()` deviendrait ambigu. On la
-- supprime donc avant de la recréer, comme pour `open_login_flow` en son temps.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Une session qui meurt n'est pas une faute : elle est
--   datée et rangée sous EXPIRED, comme les autres, et le balayage reprend sa
--   clé au passage suivant.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

DROP FUNCTION admin.expire_sessions();

CREATE FUNCTION admin.expire_sessions(
  p_pending_grace interval DEFAULT interval '5 minutes'
) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_closed integer;
BEGIN
  WITH dead AS (
    SELECT s.id,
           LEAST(
             s.absolute_expires_at,
             -- La borne de la paire. NULL quand il n'y en a pas — LEAST
             -- l'ignore, et c'est la troisième ligne qui prend le relais.
             (SELECT p.inactivity_expires_at
                FROM admin.token_pair p
               WHERE p.session_id = s.id
                 AND p.replaced_at IS NULL),
             -- La borne d'attente, et elle ne s'applique QUE si aucune paire
             -- n'existe : dès que la présence est prouvée, la session vit sa
             -- vie normale et ce délai n'a plus rien à dire.
             CASE WHEN NOT EXISTS (SELECT 1
                                     FROM admin.token_pair p
                                    WHERE p.session_id = s.id)
                  THEN s.created_at + p_pending_grace
             END
           ) AS died_at
      FROM admin.session s
     WHERE s.ended_at IS NULL
  )
  UPDATE admin.session s
     SET ended_at = d.died_at, end_reason = 'EXPIRED'
    FROM dead d
   WHERE s.id = d.id
     AND d.died_at <= now();

  GET DIAGNOSTICS v_closed = ROW_COUNT;
  RETURN v_closed;
END $$;

COMMENT ON FUNCTION admin.expire_sessions IS
'Date la mort des sessions ouvertes au plus tôt de TROIS bornes, et rend le
nombre de sessions closes.

  · le plafond absolu d''une heure, jamais repoussé ;
  · l''inactivité de la paire non remplacée, quand il y en a une ;
  · la grâce d''attente, quand il n''y en a AUCUNE — c''est-à-dire entre le
    retour du fournisseur et la preuve de présence.

La troisième existe parce que la connexion se fait en deux temps : sans elle,
une session abandonnée avant la clé matérielle vivrait une heure entière, et sa
clé privée avec elle. Elle vaut le temps du laissez-passer, pas davantage :
passé ce délai plus rien ne pouvait s''en servir de toute façon.

Aucun cron ne l''appelle. Le plan la joue à son balayage, et l''état vivant se
lit toujours de now(), jamais d''une colonne tenue à jour.';

REVOKE EXECUTE ON FUNCTION admin.expire_sessions(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.expire_sessions(interval) TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP FUNCTION admin.expire_sessions(interval);

CREATE FUNCTION admin.expire_sessions() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_closed integer;
BEGIN
  WITH dead AS (
    SELECT s.id,
           LEAST(
             s.absolute_expires_at,
             (SELECT p.inactivity_expires_at
                FROM admin.token_pair p
               WHERE p.session_id = s.id
                 AND p.replaced_at IS NULL)
           ) AS died_at
      FROM admin.session s
     WHERE s.ended_at IS NULL
  )
  UPDATE admin.session s
     SET ended_at = d.died_at, end_reason = 'EXPIRED'
    FROM dead d
   WHERE s.id = d.id
     AND d.died_at <= now();

  GET DIAGNOSTICS v_closed = ROW_COUNT;
  RETURN v_closed;
END $$;

REVOKE EXECUTE ON FUNCTION admin.expire_sessions() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.expire_sessions() TO app_admin_plane;

RESET ROLE;
