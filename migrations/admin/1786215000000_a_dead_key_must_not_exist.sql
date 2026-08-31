-- Up Migration

-- UNE CLÉ MORTE NE DOIT PAS SEULEMENT SE TAIRE, ELLE DOIT DISPARAÎTRE.
--
-- `a_key_dies_with_its_session` a fermé trois chemins et laissé le quatrième
-- ouvert, avec cette justification :
--
--     « Même raison pour destroyable_key : ce qui décide qu'un privé peut être
--       détruit, c'est la fin de la fenêtre de VÉRIFICATION, pas celle de
--       signature. »
--
-- La phrase ne survit pas à la relecture, pour deux raisons.
--
-- D'abord elle ne décrit pas le prédicat qu'elle défend : la vue teste
-- `now() >= signs_until`, qui EST la fenêtre de signature. La justification et
-- le code disent deux choses différentes.
--
-- Ensuite le raisonnement lui-même ne tient pas. Détruire le privé n'a jamais
-- gêné une vérification : elle lit `public_jwk`, qui reste dans la ligne pour
-- toujours, et `verifiable_key` continue de la publier jusqu'à
-- `published_until`. Il n'existe donc aucune raison tirée de la vérification de
-- conserver du matériel privé après la fin de la signature. Le paragraphe ne
-- protégeait rien, et il gardait en vie précisément ce qui doit disparaître.
--
--
-- ═══ CE QUI ÉTAIT EN JEU, MESURÉ ET NON SUPPOSÉ ═══
--
-- La politique du service accorde `transit/sign/admin-*`. OpenBao ne connaît ni
-- `session.ended_at`, ni `akeys.signing_key`, ni cette base. Une clé dont la
-- session était fermée depuis vingt minutes a produit une signature valide avec
-- le seul jeton du service, sans qu'aucune vue n'ait été interrogée.
--
-- Et le `kid` n'est pas un secret : il voyage en clair dans l'en-tête de chaque
-- jeton que le plan a signé pendant cette session. Le nom `admin-<kid>` est donc
-- connu de quiconque a vu passer un cookie, et l'attaque ne demande aucun accès
-- à la base — seulement le jeton, que la base ne protège pas.
--
-- Le refus de rendre `kms_ref` ne ferme que le chemin honnête. La seule défense
-- réelle est que le matériel n'existe pas.
--
--
-- ═══ LA VUE DEVIENT LE COMPLÉMENT EXACT DE signing_material ═══
--
-- Deux vues, une frontière, et plus de zone grise entre elles :
--
--     peut signer     ACTIVE, privé présent, now() < signs_until, session ouverte
--     destructible    privé présent, ET (horloge franchie OU session fermée)
--
-- La DISJONCTION est préservée, et ce n'est pas un détail d'esthétique : c'est
-- elle qui garantit que le balayage ne peut jamais détruire une clé avec
-- laquelle quelqu'un est en train de signer. Une ligne de `signing_material` a
-- son horloge devant elle et sa session ouverte, donc aucun des deux termes de
-- `destroyable_key` n'est vrai pour elle. Les deux ensembles ne se touchent pas.
--
-- L'état de la clé n'est pas filtré, comme avant : une clé restée PENDING dont
-- la session a disparu doit aussi rendre son matériel. Elle n'a jamais signé et
-- ne signera jamais, ce qui est la meilleure raison de la détruire.
--
--
-- ═══ CE QUE CETTE MIGRATION NE PEUT PAS GARANTIR SEULE ═══
--
-- Elle rend la clé destructible à l'instant où sa session se ferme. Elle ne dit
-- rien du moment où quelqu'un passera la détruire — c'est le balayage, qui est
-- paresseux et se paie sur une connexion. Une reconnexion détruit donc la
-- précédente dans la même requête, mais une déconnexion sans retour laisse le
-- matériel jusqu'à la prochaine visite. La garantie « une clé morte n'existe
-- pas » demande un déclencheur qui ne soit pas une connexion, et il n'y en a
-- pas encore.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code. Une vue ne refuse rien, elle rend moins de lignes ou plus.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE OR REPLACE VIEW akeys.destroyable_key AS
  SELECT k.id, k.kid, k.user_id, k.kms_ref, k.signs_until, k.purpose
    FROM akeys.key AS k
    INNER JOIN admin.session AS s ON k.session_id = s.id
   WHERE k.private_destroyed_at IS NULL
     AND (now() >= k.signs_until OR s.ended_at IS NOT NULL);

COMMENT ON VIEW akeys.destroyable_key IS
'Les clés dont le matériel privé existe encore alors qu''elles ne peuvent plus
signer — par l''horloge OU par la fermeture de leur session. Complément exact de
signing_material : les deux vues sont disjointes, donc le balayage ne peut jamais
détruire une clé avec laquelle on est en train de signer. Le chemin de rotation
la lit, détruit chaque référence, puis inscrit private_destroyed_at. Avec
signing_material, kms_ref est lisible exactement deux fois dans la vie d''une
clé — pendant qu''elle signe, et pendant qu''on la détruit — jamais entre les
deux ni après.';

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

CREATE OR REPLACE VIEW akeys.destroyable_key AS
  SELECT id, kid, user_id, kms_ref, signs_until, purpose
  FROM akeys.key
  WHERE private_destroyed_at IS NULL
    AND now() >= signs_until;

COMMENT ON VIEW akeys.destroyable_key IS
  'Keys whose signing window has closed but whose KMS material still exists. The rotation path reads this, destroys each reference, then posts private_destroyed_at. Together with signing_material, kms_ref is readable exactly twice in a key''s life — while it signs, and while it is being destroyed — and never in between or after.';

RESET ROLE;
