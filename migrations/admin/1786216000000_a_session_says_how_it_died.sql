-- Up Migration

-- UN CODE DE VOCABULAIRE QUE PERSONNE N'ÉCRIT EST SOIT FAUX, SOIT PAS FAIT.
--
-- `admin.session_end_reason` en déclare quatre. À ce jour :
--
--     SUPERSEDED   écrit par session_supersede
--     LOGOUT       écrit par le chemin de déconnexion
--     EXPIRED      jamais écrit
--     SECURITY     jamais écrit
--
-- `EXPIRED` porte sa propre définition : « Inactivity window or absolute ceiling
-- reached ». Le cas est nommé, daté par deux colonnes, et rien ne le constate.
--
--
-- ═══ LE CODE ÉCRIT L'EST PARFOIS À TORT ═══
--
-- Ce n'est pas qu'une lacune, c'est une erreur d'étiquetage. Un administrateur
-- qui ferme son onglet laisse une session dont le plafond tombe une heure plus
-- tard, avec `ended_at` vide. S'il revient le lendemain, `session_supersede`
-- l'étiquette SUPERSEDED — alors qu'elle a EXPIRÉ vingt-trois heures avant, et
-- que rien ne l'a supplantée. Le seul code écrit sur ce chemin est le mauvais,
-- parce que le vrai n'était pas disponible.
--
-- Et la relecture d'audit n'a pas de question uniforme à poser : pour deux codes
-- on lit une colonne, pour le troisième on compare deux horodatages et on espère
-- avoir choisi les bons.
--
--
-- ═══ LA MOITIÉ QUI COMPTE VRAIMENT EST L'INACTIVITÉ ═══
--
-- Le plafond n'est pas le cas urgent : la clé meurt avec son horloge de toute
-- façon, `signs_until` VALANT ce plafond.
--
-- L'inactivité, si. Une session laissée quinze minutes ne peut plus jamais
-- servir — `validate_bearer` et `rotate_pair` exigent tous deux
-- `now() < inactivity_expires_at`. Mais rien ne le DISAIT, donc `signing_key`
-- publiait encore sa clé pendant les quarante-cinq minutes de plafond restantes,
-- et le balayage ne la voyait pas. Une clé bien vivante, sur une session que
-- personne ne peut plus utiliser.
--
-- Fermer la session est ce qui la fait tomber. La fenêtre d'inactivité cesse
-- d'être une propriété du chemin de rafraîchissement pour devenir une propriété
-- de la SESSION — donc de sa clé, par la jointure que
-- `a_key_dies_with_its_session` a posée.
--
--
-- ═══ ended_at EST L'INSTANT DE LA MORT, PAS CELUI DU CONSTAT ═══
--
-- `now()` serait un mensonge : il dirait que la session s'est terminée quand le
-- balayage est passé. Le fait est déjà dans les lignes, et il suffit de le lire.
--
--     le plafond      session.absolute_expires_at
--     l'inactivité    inactivity_expires_at de la paire non remplacée
--     la mort         le PREMIER des deux
--
-- `LEAST` ignore les NULL, donc une session sans paire non remplacée retombe sur
-- son plafond au lieu de retomber sur rien. Ce cas ne devrait pas exister —
-- `rotate_pair` émet toujours la suivante dans la même instruction — mais une
-- fonction d'entretien qui répond faux sur des données qu'elle « ne devrait pas
-- voir » est une fonction d'entretien à laquelle on cesse de se fier.
--
--
-- ═══ PAS DE LOT, ET LA RAISON EST DANS LE CATALOGUE ═══
--
-- Les autres purges sont bornées par `admin.retention.batch_size`. Celle-ci n'en
-- a pas besoin : `uq_session_mono` n'admet qu'une session non close par
-- administrateur, donc le nombre de lignes à fermer est au plus le nombre
-- d'administrateurs. Deux ou trois, pour toujours.
--
--
-- ═══ CE QUI RESTE NON ÉCRIT ═══
--
-- `SECURITY` — le rejeu d'un refresh détecté. `consume_pair` et `rotate_pair`
-- rendent zéro ligne sur un rejeu et documentent la réaction attendue, mais
-- aucun appelant ne l'implémente encore. Le code reste donc au catalogue sans
-- écrivain, et c'est noté ici pour que le trou soit consigné plutôt que
-- redécouvert.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Fermer une session déjà close ne se produit pas : le
--   prédicat ne regarde que ended_at IS NULL, et zéro ligne n'est pas une erreur.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE FUNCTION admin.expire_sessions()
RETURNS integer
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

COMMENT ON FUNCTION admin.expire_sessions IS
'Constate la mort des sessions que personne n''a fermées, et la date à l''instant
où elle a eu lieu : le premier du plafond absolu et de la fenêtre d''inactivité de
la paire encore en place. Jamais now(), qui ne dirait que l''heure du constat.

Ce n''est pas de la cosmétique d''audit. Une session inactive depuis quinze
minutes ne peut plus servir — validate_bearer et rotate_pair l''exigent tous deux
— mais tant qu''elle n''est pas CLOSE, signing_key publie encore sa clé pour le
reliquat de son plafond. La fermer est ce qui retire la clé, et ce qui libère la
place que uq_session_mono lui réservait pour rien.

Rend le nombre de sessions closes. Non bornée délibérément : uq_session_mono
n''admet qu''une session ouverte par administrateur, donc le travail est majoré
par le nombre d''administrateurs.';

REVOKE EXECUTE ON FUNCTION admin.expire_sessions() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.expire_sessions() TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

-- Les sessions déjà closes en EXPIRED le restent : c'est un fait daté, et une
-- rétrogradation n'a pas à effacer un constat juste. Elle retire seulement le
-- moyen d'en faire de nouveaux.
DROP FUNCTION admin.expire_sessions();

RESET ROLE;
