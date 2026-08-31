-- Up Migration

-- UNE PREUVE DE POSSESSION EST ELLE-MÊME UN PORTEUR.
--
-- `the_binding_is_declared_before_the_session` a fermé le vol du COOKIE seul :
-- sans la clé privée, le jeton ne vaut plus rien. Mais la preuve qui accompagne
-- la requête est, elle, un artefact que quiconque la capture peut représenter.
-- Elle ne couvre que la méthode, l'adresse et l'instant ; à l'intérieur de sa
-- fenêtre de fraîcheur, la rejouer telle quelle fonctionne.
--
-- Cette table est ce qui fait qu'une preuve ne sert qu'UNE fois.
--
--
-- ═══ POURQUOI ICI ET PAS DANS UN CACHE EXTERNE ═══
--
-- Un magasin dédié — Redis ou équivalent — ajouterait une seconde dépendance À
-- ÉTAT à un plan de contrôle, et avec elle une question qui n'a pas de bonne
-- réponse : que fait le plan quand ce magasin est indisponible ? Accepter les
-- rejeux, ou refuser toute administration. Ici, si la base est absente le plan
-- est déjà hors service — le contrôle ne crée AUCUN mode de panne nouveau.
--
-- Le débit ne l'exige pas davantage : deux ou trois administrateurs, une fenêtre
-- de soixante secondes, donc quelques dizaines de lignes vivantes. Et
-- l'atomicité que le contrôle demande est celle que cette base pratique déjà
-- partout : `ON CONFLICT DO NOTHING ... RETURNING` décide en UNE instruction,
-- exactement comme `consume_pair` ou `verify_presence`. Zéro ligne signifie
-- « déjà dépensée », sans qu'un SELECT préalable — qui serait la course — ait
-- eu lieu.
--
--
-- ═══ LA RÉTENTION N'EST PAS UNE POLITIQUE, ELLE EST SUR LA LIGNE ═══
--
-- Les autres relations purgeables ont une ligne dans `admin.retention`, parce
-- que « combien de temps garde-t-on ça » est une décision. Ici ce n'en est pas
-- une : une preuve dépensée n'a besoin d'être retenue que jusqu'à la fin de SA
-- fenêtre de fraîcheur, puisque au-delà le contrôle de fraîcheur la refuse de
-- toute façon. La retenir plus longtemps ne protège de rien.
--
-- La table est donc auto-limitée, et volontairement absente d'`admin.retention` :
-- y inscrire un `keep_for` laisserait croire qu'on peut le régler, alors que la
-- seule valeur juste est déjà dans chaque ligne.
--
--
-- ═══ CE QUE ÇA NE FERME TOUJOURS PAS ═══
--
-- La pré-fabrication. Qui contrôle brièvement le navigateur peut se constituer
-- un stock de preuves signées et les dépenser plus tard, une par une — chacune
-- neuve, donc aucune n'est un rejeu. Fermer ça demande un défi émis par le
-- serveur (RFC 9449 §8), donc un aller-retour supplémentaire à chaque première
-- requête. C'est le pas d'après, pas celui-ci.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code. Une preuve déjà dépensée rend ZÉRO LIGNE, jamais une exception :
--   l'appelant refuse sans avoir à distinguer, et un rejeu n'est pas une panne.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE TABLE admin.spent_proof (
  jti        uuid        PRIMARY KEY,
  session_id uuid        NOT NULL REFERENCES admin.session(id) ON DELETE RESTRICT,
  spent_at   timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

-- L'index qui sert la purge. La clé primaire sert le contrôle ; celui-ci sert le
-- ménage, et sans lui le balayage relit toute la table à chaque passage.
CREATE INDEX ix_spent_proof_purgeable ON admin.spent_proof (expires_at);

COMMENT ON TABLE admin.spent_proof IS
'Les preuves de possession déjà dépensées, le temps que leur fenêtre de fraîcheur
se referme. C''est ce qui fait qu''une preuve capturée ne sert pas deux fois. La
clé primaire porte la garantie : une seconde écriture du même jti ne passe pas,
et l''appelant lit zéro ligne plutôt qu''une erreur.

Éphémère et purgeable, comme webauthn.challenge — aucune valeur d''audit, et donc
pas d''append-only. Absente d''admin.retention délibérément : sa durée de vie est
sur chaque ligne et non dans une politique.';

COMMENT ON COLUMN admin.spent_proof.expires_at IS
  'La fin de la fenêtre de fraîcheur de CETTE preuve, calculée par l''appelant qui la vérifie. Au-delà, la retenir ne protège plus : le contrôle de fraîcheur la refuse déjà.';

-- ---------------------------------------------------------------------
-- Dépenser, en une instruction.
-- ---------------------------------------------------------------------
CREATE FUNCTION admin.spend_proof(
  p_jti        uuid,
  p_session_id uuid,
  p_expires_at timestamptz
) RETURNS TABLE (jti uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  INSERT INTO admin.spent_proof AS sp (jti, session_id, expires_at)
  VALUES (p_jti, p_session_id, p_expires_at)
  ON CONFLICT (jti) DO NOTHING
  RETURNING sp.jti;
$$;

COMMENT ON FUNCTION admin.spend_proof IS
'Dépense une preuve. Rend une ligne la première fois, zéro ensuite — et zéro veut
dire rejeu, sans ambiguïté, parce que la fraîcheur a déjà été vérifiée par
l''appelant avant d''arriver ici. Jamais un SELECT puis un INSERT : ce SELECT
serait précisément la course qu''on cherche à fermer.';

-- ---------------------------------------------------------------------
-- Le ménage. Borné, comme les autres, et rendant son compte.
-- ---------------------------------------------------------------------
CREATE FUNCTION admin.purge_spent_proofs()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_deleted integer;
BEGIN
  WITH doomed AS (
    SELECT sp.jti
      FROM admin.spent_proof sp
     WHERE sp.expires_at < now()
     LIMIT 5000
  )
  DELETE FROM admin.spent_proof sp USING doomed d WHERE sp.jti = d.jti;

  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END $$;

COMMENT ON FUNCTION admin.purge_spent_proofs IS
  'Retire les preuves dont la fenêtre est close. Aucune politique à consulter : une preuve périmée est refusée par la fraîcheur, donc la garder ne protège plus de rien. Bornée pour qu''un retard accumulé ne se paie pas en une fois, et rend son compte pour qui veut boucler.';

CREATE VIEW api.spent_proof AS
  SELECT jti, session_id, spent_at, expires_at FROM admin.spent_proof;

REVOKE EXECUTE ON FUNCTION admin.spend_proof(uuid, uuid, timestamptz) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.purge_spent_proofs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.spend_proof(uuid, uuid, timestamptz) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.purge_spent_proofs() TO app_admin_plane;
GRANT SELECT ON api.spent_proof TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP VIEW api.spent_proof;
DROP FUNCTION admin.purge_spent_proofs();
DROP FUNCTION admin.spend_proof(uuid, uuid, timestamptz);
DROP TABLE admin.spent_proof;

RESET ROLE;
