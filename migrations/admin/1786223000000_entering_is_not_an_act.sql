-- Up Migration

-- ENTRER N'EST PAS AGIR, ET LES DEUX PREUVES NE SE RESSEMBLENT PAS.
--
-- `verify_presence` est la porte des actes lourds, et elle exige tout ce qu'un
-- acte exige : un défi frappé pour UNE action du vocabulaire, UNE portée, UNE
-- cible, et `may_operate` relu à la consommation.
--
-- La seconde étape de la CONNEXION n'est rien de tout ça. Elle ne demande pas
-- « as-tu le droit de résilier ce client », elle demande « es-tu bien toi ». Lui
-- faire emprunter le même chemin la casserait de deux façons :
--
--   · il faudrait inventer une action au vocabulaire des COMMANDES SIGNÉES pour
--     un geste qui n'en produit aucune ;
--   · `may_operate` refuserait tout administrateur sans autorité — c'est-à-dire
--     qu'il faudrait des droits pour se connecter, alors que l'ordre est
--     exactement l'inverse : on se connecte, puis on relit ce qu'on peut faire.
--
-- Les deux preuves restent donc séparées, et c'est le sens de cette migration :
-- ouvrir le SEUL geste que la connexion partage avec un acte — faire avancer le
-- compteur anti-clonage — sans ouvrir le reste.
--
--
-- ═══ POURQUOI LE COMPTEUR NE PEUT PAS RESTER DEHORS ═══
--
-- `sign_count` n'a aucun GRANT en UPDATE, délibérément : « granting sign_count
-- here would allow the counter to be moved without an assertion ». Il ne bouge
-- que par `verify_presence`.
--
-- Si la connexion ne passe pas par là, ses assertions n'avancent rien — et un
-- authentificateur cloné pourrait servir à entrer indéfiniment sans que
-- `sign_count_guard` ne dise jamais rien. Le contrôle anti-clonage existerait
-- pour les actes lourds et pas pour la porte d'entrée, ce qui est l'inverse de
-- l'ordre d'arrivée d'un attaquant.
--
--
-- ═══ CE QUE CETTE FONCTION NE FAIT PAS ═══
--
-- Elle ne consomme aucun défi — la connexion garde le sien dans un cookie, comme
-- l'enrôlement, parce qu'un défi d'entrée n'autorise aucun acte et n'a donc rien
-- à faire dans une table qui lie un défi à une action.
--
-- Elle ne lit AUCUNE autorité. C'est le point : entrer ne demande rien d'autre
-- que d'être qui l'on dit.
--
-- Elle ne vérifie pas la signature. C'est fait avant, en Go, contre la clé
-- publique rangée à l'enrôlement — et l'appelant n'arrive ici qu'une fois cette
-- vérification passée. La base tient l'invariant du COMPTEUR ; elle n'a jamais
-- prétendu tenir la cryptographie.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Un compteur qui n'avance pas lève AD031, levé par
--   `sign_count_guard` comme sur n'importe quelle autre assertion — c'est
--   précisément pour qu'il le lève ici aussi que cette fonction existe.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE FUNCTION webauthn.note_assertion(
  p_user_id       uuid,
  p_credential_id bytea,
  p_sign_count    bigint
) RETURNS TABLE (id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  UPDATE webauthn.authenticator a
     SET sign_count = p_sign_count
   WHERE a.credential_id = p_credential_id
     AND a.user_id       = p_user_id
     AND a.revoked_at IS NULL
  RETURNING a.id;
$$;

COMMENT ON FUNCTION webauthn.note_assertion IS
'Avance le compteur anti-clonage après une assertion d''ENTRÉE — la seconde étape
de la connexion, qui prouve une identité et non un droit.

Zéro ligne signifie : accréditation inconnue, révoquée, ou appartenant à un autre
administrateur. Un compteur qui ne progresse pas strictement lève AD031, comme
partout ailleurs : c''est le seul but de cette fonction, puisque sans elle les
assertions de connexion n''avanceraient rien et qu''un authentificateur cloné
pourrait entrer sans fin.

Elle ne consomme aucun défi et ne lit aucune autorité. verify_presence reste la
porte des actes lourds, et elle exige les deux.';

REVOKE EXECUTE ON FUNCTION webauthn.note_assertion(uuid, bytea, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION webauthn.note_assertion(uuid, bytea, bigint) TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP FUNCTION webauthn.note_assertion(uuid, bytea, bigint);

RESET ROLE;
