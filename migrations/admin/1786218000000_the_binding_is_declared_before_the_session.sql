-- Up Migration

-- LA LIAISON SE DÉCLARE AVANT LA SESSION, PARCE QU'APRÈS IL EST TROP TARD.
--
-- `the_admin_token_is_bound` a posé `session.cnf_jkt`, sa contrainte de forme, et
-- `session_binding_is_immutable` qui refuse (AD014) de la changer ensuite — « on
-- ouvre une NOUVELLE session, on ne repeint pas l'ancienne ». Puis elle a écrit
-- ce qui restait à faire :
--
--     « Ce qui reste à la bordure : refuser d'ouvrir une session
--       d'administration sans liaison. »
--
-- Rien ne l'écrivait. `admin.unbound_session` — la vue faite pour que « combien
-- de sessions ne sont pas liées » ait une réponse chiffrée — les compte toutes.
--
--
-- ═══ L'IMMUABILITÉ DÉCIDE DU MOMENT ═══
--
-- Puisque la liaison ne peut pas être posée après coup, elle doit être là à
-- l'INSERT de la session. Or la session naît dans le callback, où le navigateur
-- arrive d'Entra par une redirection : il ne peut y attacher aucune preuve.
--
-- Elle doit donc être déclarée AVANT le départ, au `/login`, et voyager avec le
-- flux — exactement comme `redirect_to`, et pour une raison voisine : c'est une
-- décision prise à l'ouverture, que l'aller-retour doit rapporter intacte.
--
--
-- ═══ UNE EMPREINTE N'EST PAS UN SECRET ═══
--
-- `cnf_jkt` est le SHA-256 d'une clé PUBLIQUE. La faire voyager en clair, dans
-- une chaîne de requête ou dans une table, ne donne rien à personne : ce qui
-- protège, c'est de détenir la clé privée, qui ne quitte jamais le navigateur.
--
-- C'est la différence entre cette colonne et `code_verifier`, deux lignes plus
-- haut dans la même table : l'un est un secret qui vit dix minutes, l'autre une
-- empreinte qu'on pourrait publier.
--
-- Même contrainte de forme que sur la session — 43 caractères base64url — pour
-- que les deux colonnes se lisent pareil, et pour qu'une valeur mal formée soit
-- refusée à l'entrée du flux plutôt qu'à l'ouverture de la session, quand
-- l'aller-retour chez Entra a déjà eu lieu.
--
--
-- ═══ DÉTRUIRE ET RECRÉER, PAS REMPLACER ═══
--
-- `CREATE OR REPLACE FUNCTION` avec un paramètre de plus ne remplace rien : il
-- SURCHARGE. Les deux versions coexisteraient, et un appel à quatre arguments
-- deviendrait ambigu entre l'ancienne signature et la nouvelle à défaut.
-- Changer un type de retour est refusé tout court.
--
-- Les deux fonctions tombent donc et renaissent, et leurs droits sont reposés —
-- une fonction recréée revient avec EXECUTE accordé à PUBLIC, ce qui sur une
-- SECURITY DEFINER prêterait les droits du propriétaire à tout le cluster.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Une empreinte mal formée est refusée par la contrainte
--   de forme, donc par un 23514 standard, comme sur la session.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

ALTER TABLE admin.login_flow
  ADD COLUMN cnf_jkt text;

ALTER TABLE admin.login_flow
  ADD CONSTRAINT flow_cnf_jkt_shape CHECK (
    cnf_jkt IS NULL OR cnf_jkt ~ '^[A-Za-z0-9_-]{43}$');

COMMENT ON COLUMN admin.login_flow.cnf_jkt IS
'L''empreinte de la clé du porteur, déclarée au départ parce que la session ne
peut plus la recevoir une fois née (AD014). Une empreinte de clé publique n''est
pas un secret : contrairement à code_verifier deux colonnes plus haut, elle peut
voyager en clair. Ce qui protège est la clé privée, qui ne quitte pas le
navigateur.';

DROP FUNCTION admin.open_login_flow(text, text, text, text);

CREATE FUNCTION admin.open_login_flow(
  p_state    text,
  p_nonce    text,
  p_verifier text,
  p_redirect text DEFAULT NULL,
  p_cnf_jkt  text DEFAULT NULL
) RETURNS uuid
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  INSERT INTO admin.login_flow (state, nonce, code_verifier, redirect_to, cnf_jkt, expires_at)
  VALUES (p_state, p_nonce, p_verifier, p_redirect, p_cnf_jkt, now() + interval '10 minutes')
  RETURNING id;
$$;

COMMENT ON FUNCTION admin.open_login_flow IS
'Ouvre un flux de connexion et rend son identifiant. La fenêtre de dix minutes est
ici et non chez l''appelant : il est anonyme, et la durée de vie d''un jeton
anti-rejeu n''est pas une décision d''appelant. Un state déjà présent lève 23505
plutôt que d''écraser un flux en cours. L''empreinte du porteur est facultative en
base et exigée à la bordure : la base reste utilisable par un client qui ne sait
pas encore se lier, l''application refuse de le laisser administrer.';

DROP FUNCTION admin.consume_login_flow(text);

CREATE FUNCTION admin.consume_login_flow(p_state text)
RETURNS TABLE (nonce text, code_verifier text, redirect_to text, cnf_jkt text)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  UPDATE admin.login_flow
     SET consumed_at = now()
   WHERE state = p_state
     AND consumed_at IS NULL
     AND now() < expires_at
  RETURNING nonce, code_verifier, redirect_to, cnf_jkt;
$$;

COMMENT ON FUNCTION admin.consume_login_flow IS
'Consomme un flux en une instruction et rend ce qu''il gardait. Zéro ligne signifie
inconnu, déjà consommé ou expiré — jamais une exception, l''appelant refuse sans
distinguer. L''empreinte revient avec le reste : elle a été déclarée au départ, et
la session qui suit doit la porter dès son INSERT.';

-- `api.login_flow` n'est PAS touchée. Elle ne publie que le cycle de vie — id,
-- création, échéance, consommation — et pas une ligne des secrets du flux. Y
-- ajouter l'empreinte ne servirait personne : l'application passe par les
-- fonctions, et une colonne de plus dans une vue d'observation est une colonne
-- que quelqu'un finira par lire au lieu de demander.

-- `live_session` non plus, et j'ai commencé par l'élargir avant de revenir en
-- arrière. Sa liste de colonnes est figée avant cnf_jkt, donc l'étendre est
-- possible — mais `admin.live_pair` s'appuie dessus, et la rétrograder
-- exigerait de détruire puis recréer les quatre vues de la chaîne avec leurs
-- droits. Un aller simple confortable et un retour coûteux.
--
-- La liaison se lit donc là où elle est CONTRÔLÉE : à la résolution d'un jeton,
-- par `SessionOfLiveToken`, qui joint déjà la paire vivante à sa session. Le
-- chemin qui doit vérifier une preuve est celui qui demande sous quelle
-- empreinte vérifier, et aucune vue n'a besoin de changer de forme.

REVOKE EXECUTE ON FUNCTION admin.open_login_flow(text, text, text, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.consume_login_flow(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.open_login_flow(text, text, text, text, text) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.consume_login_flow(text) TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP FUNCTION admin.consume_login_flow(text);

CREATE FUNCTION admin.consume_login_flow(p_state text)
RETURNS TABLE (nonce text, code_verifier text, redirect_to text)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  UPDATE admin.login_flow
     SET consumed_at = now()
   WHERE state = p_state
     AND consumed_at IS NULL
     AND now() < expires_at
  RETURNING nonce, code_verifier, redirect_to;
$$;

DROP FUNCTION admin.open_login_flow(text, text, text, text, text);

CREATE FUNCTION admin.open_login_flow(
  p_state    text,
  p_nonce    text,
  p_verifier text,
  p_redirect text DEFAULT NULL
) RETURNS uuid
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  INSERT INTO admin.login_flow (state, nonce, code_verifier, redirect_to, expires_at)
  VALUES (p_state, p_nonce, p_verifier, p_redirect, now() + interval '10 minutes')
  RETURNING id;
$$;

REVOKE EXECUTE ON FUNCTION admin.open_login_flow(text, text, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.consume_login_flow(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.open_login_flow(text, text, text, text) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.consume_login_flow(text) TO app_admin_plane;

ALTER TABLE admin.login_flow DROP CONSTRAINT flow_cnf_jkt_shape;
ALTER TABLE admin.login_flow DROP COLUMN cnf_jkt;

RESET ROLE;
