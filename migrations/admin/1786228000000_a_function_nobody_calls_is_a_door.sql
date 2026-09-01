-- Up Migration

-- UNE FONCTION QUE PERSONNE N'APPELLE EST UNE PORTE QU'ON A OUBLIÉ DE FERMER.
--
-- `admin.consume_pair` remplace une paire de jetons par rien : elle pose
-- `replaced_at` sur la paire vivante d'une session et rend son identifiant. Elle
-- est accordée à `app_admin_plane` depuis le premier jour.
--
-- Elle n'a AUCUN APPELANT. `/refresh` utilise `rotate_pair`, qui consomme et
-- réémet dans le même geste — ce qui est précisément le point : consommer sans
-- réémettre laisse une session vivante sans paire vivante, un état que rien dans
-- le plan ne sait plus rattraper. L'administrateur devrait se reconnecter, sans
-- que rien ne le lui dise.
--
-- C'est donc une capacité offerte au rôle applicatif dont le seul usage possible
-- est de mettre quelqu'un dehors en silence.
--
--
-- ═══ LA RÈGLE EST DÉJÀ ÉCRITE AILLEURS ═══
--
-- Le banc d'essai ne se monte pas derrière un 403 : « une route déclarée puis
-- gardée par un 403 est une route qui existe, donc une surface qu'on peut
-- oublier ouverte ; celle-ci n'existe pas du tout sans le drapeau. »
--
-- Le raisonnement ne change pas parce qu'il s'agit d'une fonction SQL plutôt que
-- d'une route HTTP. Retirer le GRANT suffirait à la rendre inoffensive
-- aujourd'hui ; la supprimer la rend inoffensive le jour où quelqu'un
-- réaccordera des droits en masse sans relire ce fichier.
--
--
-- ═══ CE QUE ÇA NE COÛTE PAS ═══
--
-- Rien ne la référence : ni vue, ni contrainte, ni autre fonction. Les seules
-- mentions du nom sont dans des commentaires — dont un que j'ai écrit moi-même
-- dans `1786224000000` en lui prêtant la signature de `rotate_pair`, ce qui
-- montre assez bien qu'une fonction morte finit par être citée de travers.
--
-- La descente la recrée à l'identique, GRANT compris : une migration réversible
-- doit rendre exactement ce qu'elle a pris, y compris ce qu'elle jugeait inutile.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. On retire une capacité, on n'en refuse aucune.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

DROP FUNCTION admin.consume_pair(admin.uuid_v4);

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

CREATE FUNCTION admin.consume_pair(p_jti_refresh admin.uuid_v4)
RETURNS TABLE (session_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  UPDATE admin.token_pair p
     SET replaced_at = now()
    FROM admin.session s
   WHERE p.jti_refresh = p_jti_refresh
     AND p.replaced_at IS NULL
     AND s.id = p.session_id
     AND s.ended_at IS NULL
     AND now() < p.inactivity_expires_at
     AND now() < s.absolute_expires_at
  RETURNING p.session_id;
$$;

REVOKE EXECUTE ON FUNCTION admin.consume_pair(admin.uuid_v4) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.consume_pair(admin.uuid_v4) TO app_admin_plane;

RESET ROLE;
