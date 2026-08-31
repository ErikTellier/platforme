-- Up Migration

-- UNE CONNEXION COMMENCE AVANT QU'IL Y AIT QUELQU'UN.
--
-- `webauthn.challenge` porte `session_id NOT NULL` et une clé étrangère
-- composite vers `(session.id, session.user_id)`. C'est ce qui la rend sûre :
-- une preuve de présence appartient à la session qui l'a demandée, elle ne peut
-- pas être collectée sous une session et dépensée sous une autre, et une
-- reconnexion — qui remplace la session précédente — invalide gratuitement tout
-- ce qui est en vol.
--
-- Le flux OIDC ne peut rien avoir de tel. Au moment du `/login` il n'y a ni
-- session, ni identité, ni utilisateur : c'est exactement ce que l'aller-retour
-- vers Entra va établir. Cette table est donc la seule du schéma QU'ON ÉCRIT
-- SANS SAVOIR QUI ÉCRIT, et tout ce qui suit découle de ce seul fait.
--
--
-- ═══ CE QU'ELLE GARDE, ET POURQUOI CHAQUE COLONNE ═══
--
--   state          Le lien entre le départ et le retour. Il prouve que le
--                  callback appartient au flux que CE navigateur a ouvert.
--                  Sans lui, on se fait servir un callback fabriqué et on
--                  ouvre une session sur le compte de l'attaquant.
--
--   nonce          Recopié par Entra dans l'ID token. Il prouve que le jeton
--                  répond à CETTE demande d'authentification et non à une
--                  autre, obtenue ailleurs et rejouée ici.
--
--   code_verifier  PKCE. Le secret dont seule l'empreinte est partie chez
--                  Entra. Il prouve que celui qui échange le code est celui
--                  qui l'a demandé — la seule protection réelle contre
--                  l'injection d'un code volé, que le `state` ne couvre pas :
--                  un attaquant forge son propre `state` cohérent avec son
--                  propre cookie et y glisse le code d'un autre.
--
-- Les trois sont éphémères et sans valeur une fois le flux consommé. Aucun
-- n'est un secret durable : ils vivent dix minutes.
--
--
-- ═══ TROIS CHOSES QU'ELLE NE FAIT PAS, ET IL FAUT LES SAVOIR ═══
--
--   1. AUCUNE EMPREINTE. Ni adresse, ni agent utilisateur. Les deux sont sous
--      le contrôle de celui qu'on voudrait démasquer — il lui suffit de
--      recopier un en-tête — donc elles ne protègent de rien, tandis que
--      contraindre le retour sur l'adresse casserait pour de vrai : sortie NAT
--      qui bascule, bureau vers 4G, VPN qui reprend la main. Elles ne
--      vaudraient que comme trace, et une trace se pose sur `admin.session`,
--      où il y a quelqu'un à tracer.
--
--   2. AUCUN AUDIT. Les seules colonnes qui diraient quelque chose sont les
--      trois secrets, et `audit.event` refuse d'être un chemin d'exfiltration.
--      Le reste — une tentative anonyme qui n'aboutit pas — est du bruit, pas
--      une preuve. Cette table n'est donc pas surveillée, et c'est délibéré.
--
--   3. AUCUNE RLS. Il n'y a rien pour cloisonner : pas de porteur, pas de
--      client, pas d'utilisateur. La frontière est ailleurs, et elle est plus
--      forte — l'application n'a AUCUN privilège sur la table. Elle ne peut
--      pas la nommer. Elle appelle deux fonctions, et ne récupère jamais que
--      le flux dont elle présente déjà l'état.
--
--
-- ═══ LA DURÉE DE VIE N'EST PAS UN PARAMÈTRE ═══
--
-- `webauthn.challenge` laisse l'appelant fournir `expires_at`, et c'est
-- cohérent là-bas : l'appelant est authentifié, la fenêtre dépend de l'action.
-- Ici l'appelant est anonyme. Combien de temps vit un jeton anti-rejeu n'est
-- pas une décision d'appelant, et aucune raison légitime ne demanderait dix
-- minutes de plus. La fenêtre est donc dans la fonction.
--
--
-- ═══ LA PURGE EST LA MÊME QUE CELLE DES DÉFIS ═══
--
-- Même politique dans `admin.retention`, même lot borné, même retour du nombre
-- supprimé, même refus d'inventer un défaut quand la ligne de politique
-- manque. Un flux VIVANT n'est jamais candidat, quel que soit son âge :
-- quelqu'un est peut-être en train de saisir son mot de passe chez Entra.
--
-- Et comme cette table est la seule qu'un anonyme peut faire grossir, la purge
-- a ici une seconde fonction : elle borne ce qu'un flot de requêtes sur
-- `/login` peut laisser derrière lui. Le débit se traite en amont, au proxy,
-- mais la fenêtre courte fait que rien ne s'accumule au-delà d'une journée.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers or functions (custom SQLSTATE):
--     (aucun — un flux inconnu, déjà consommé ou expiré rend ZÉRO LIGNE et
--      jamais une exception, exactement comme la consommation d'un défi.
--      L'appelant qui ne reçoit pas de ligne refuse, sans avoir à distinguer
--      laquelle des trois raisons s'applique — et sans la révéler.)
--
--   STANDARD codes, enforced by constraints:
--     23505  unique_violation — deux flux pour le même state
--     23514  check_violation  — forme du state, du nonce, du verifier, ou
--                               redirection non locale
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE TABLE admin.login_flow (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  state         text NOT NULL,
  nonce         text NOT NULL,
  code_verifier text NOT NULL,
  redirect_to   text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  consumed_at   timestamptz,

  CONSTRAINT flow_expiry_after_creation
    CHECK (expires_at > created_at),
  CONSTRAINT flow_consumed_after_creation
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),

  -- 32 octets en base64url, comme cnf_jkt. La forme est vérifiée par le moteur
  -- pour qu'un état à faible entropie ne puisse pas entrer par un bug
  -- applicatif : c'est la seule chose qui rend le state imprévisible.
  CONSTRAINT flow_state_shape CHECK (char_length(state) = 43),
  CONSTRAINT flow_nonce_shape CHECK (char_length(nonce) = 43),

  -- RFC 7636 section 4.1 : de 43 à 128 caractères.
  CONSTRAINT flow_verifier_shape
    CHECK (char_length(code_verifier) BETWEEN 43 AND 128),

  -- Une redirection après connexion devient une redirection ouverte dès
  -- qu'elle accepte un hôte. Seul un chemin local passe, et `//ailleurs` est un
  -- chemin protocole-relatif, donc un hôte déguisé en chemin.
  CONSTRAINT flow_redirect_is_local
    CHECK (redirect_to IS NULL
           OR (redirect_to LIKE '/%' AND redirect_to NOT LIKE '//%'))
);

CREATE UNIQUE INDEX uq_login_flow_state ON admin.login_flow (state);

-- La purge balaie par âge. `webauthn.challenge` s'en passe parce que seuls des
-- porteurs authentifiés l'alimentent, à raison de quelques lignes par jour.
-- Celle-ci est ouverte à l'anonyme, donc son balayage mérite un index.
CREATE INDEX ix_login_flow_purgeable ON admin.login_flow (created_at);

COMMENT ON TABLE admin.login_flow IS
  'État d''un aller-retour OIDC en cours, entre le départ vers Entra et le retour sur le callback. La seule table du schéma écrite sans porteur authentifié, parce qu''elle précède la session qu''elle sert à ouvrir. Usage unique, dix minutes, purgée paresseusement. Avec webauthn.challenge, la seconde et dernière table non append-only : un flux dépensé ne vaut plus rien.';
COMMENT ON COLUMN admin.login_flow.state IS
  'Le lien entre le départ et le retour, renvoyé tel quel par Entra. Il atteste que le callback appartient au flux ouvert par ce navigateur. Il ne dit RIEN de la provenance du code d''autorisation — c''est le rôle du verifier.';
COMMENT ON COLUMN admin.login_flow.nonce IS
  'Recopié par Entra dans l''ID token. Vérifié à la lecture du jeton : il atteste que celui-ci répond à cette demande précise, et pas à une autre obtenue ailleurs.';
COMMENT ON COLUMN admin.login_flow.code_verifier IS
  'PKCE, RFC 7636. Seule son empreinte SHA-256 est partie chez Entra. Un code d''autorisation volé et injecté dans un autre flux échoue à l''échange, parce que le verifier présenté ne correspond pas à l''empreinte enregistrée avec ce code.';
COMMENT ON COLUMN admin.login_flow.redirect_to IS
  'Où renvoyer l''utilisateur une fois connecté. Chemin local uniquement, contrainte portée par le moteur : une redirection après authentification est la forme la plus commode de redirection ouverte.';
COMMENT ON COLUMN admin.login_flow.consumed_at IS
  'Dépense du flux. Posé par admin.consume_login_flow dans le même UPDATE que la lecture, jamais par un SELECT suivi d''un UPDATE.';

-- ---------------------------------------------------------------------
-- Le chemin d'écriture. L'application n'a aucun privilège sur la table.
-- ---------------------------------------------------------------------
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

COMMENT ON FUNCTION admin.open_login_flow IS
  'Ouvre un flux de connexion et rend son identifiant. La fenêtre de dix minutes est ici et non chez l''appelant : il est anonyme, et la durée de vie d''un jeton anti-rejeu n''est pas une décision d''appelant. Un state déjà présent lève 23505 plutôt que d''écraser un flux en cours.';

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

COMMENT ON FUNCTION admin.consume_login_flow IS
  'Dépense un flux et rend ce qu''il portait, en UN SEUL UPDATE — jamais un SELECT puis un UPDATE, sans quoi deux callbacks concurrents consommeraient le même flux. Zéro ligne signifie inconnu, déjà consommé ou expiré : l''appelant refuse sans avoir à distinguer, et sans le révéler.';

-- ---------------------------------------------------------------------
-- La purge, calquée sur webauthn.purge_challenges.
-- ---------------------------------------------------------------------
CREATE FUNCTION admin.purge_login_flows()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_keep    interval;
  v_batch   integer;
  v_deleted integer;
BEGIN
  SELECT keep_for, batch_size INTO v_keep, v_batch
    FROM admin.retention WHERE relation = 'admin.login_flow';

  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  WITH doomed AS (
    SELECT f.id
      FROM admin.login_flow f
     WHERE f.created_at < now() - v_keep
       -- Dépensé ou expiré seulement. Un flux vivant est quelqu'un en train de
       -- s'authentifier chez Entra ; son âge ne suffit jamais à l'annuler.
       AND (f.consumed_at IS NOT NULL OR f.expires_at < now())
     LIMIT v_batch
  )
  DELETE FROM admin.login_flow f USING doomed d WHERE f.id = d.id;

  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END $$;

COMMENT ON FUNCTION admin.purge_login_flows IS
  'Supprime au plus batch_size flux plus vieux que admin.retention.keep_for et déjà dépensés ou expirés, et rend combien. Un flux vivant n''est jamais candidat, quel que soit son âge. Rend 0 quand il n''y a pas de ligne de politique, plutôt que d''inventer un défaut. À appeler sur le chemin de l''OUVERTURE d''un flux, pas sur celui du callback : les lignes naissent à l''ouverture, alors que le callback ne se déclenche qu''en cas de succès — le cas où il y a le moins à nettoyer. Sur le chemin qui crée, un flot de tentatives paie son propre balayage.';

-- ON CONFLICT parce que la ligne SURVIT à l'annulation de cette migration :
-- `no_delete_retention` interdit de la retirer, et c'est délibéré — une ligne
-- de politique supprimée désactive une purge en silence. Une réapplication ne
-- doit donc pas buter sur la clé primaire, ni écraser une fenêtre que
-- l'exploitation aurait ajustée entre-temps.
INSERT INTO admin.retention (relation, keep_for) VALUES
  ('admin.login_flow', interval '1 day')
ON CONFLICT (relation) DO NOTHING;

-- ---------------------------------------------------------------------
-- La vue d'observation. Les trois secrets n'y sont pas : on peut compter les
-- tentatives et mesurer combien aboutissent, sans pouvoir en détourner une.
-- ---------------------------------------------------------------------
CREATE VIEW api.login_flow AS
  SELECT id, created_at, expires_at, consumed_at
    FROM admin.login_flow;

COMMENT ON VIEW api.login_flow IS
  'Les flux de connexion, sans state, sans nonce et sans verifier. De quoi observer le volume et le taux d''aboutissement des connexions, de quoi ne rien en faire d''autre.';

REVOKE EXECUTE ON FUNCTION admin.open_login_flow(text, text, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.consume_login_flow(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.purge_login_flows() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION admin.open_login_flow(text, text, text, text) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.consume_login_flow(text) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.purge_login_flows() TO app_admin_plane;

GRANT SELECT ON api.login_flow TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP VIEW api.login_flow;
DROP FUNCTION admin.purge_login_flows();
DROP FUNCTION admin.consume_login_flow(text);
DROP FUNCTION admin.open_login_flow(text, text, text, text);
DROP TABLE admin.login_flow;

-- La ligne de politique reste. `no_delete_retention` la protège, et le
-- commentaire de la table dit pourquoi : une ligne retirée éteint une purge
-- sans bruit. Elle décrit une relation absente, ce qui ne coûte rien — la
-- fonction qui la lisait n'existe plus non plus.

RESET ROLE;
