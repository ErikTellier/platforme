-- Up Migration

-- UNE SECONDE CONNEXION EXIGE UNE SECONDE CLÉ.
--
-- `uq_key_one_active_per_purpose` disait « au plus une clé vivante par
-- administrateur et par usage ». Il tenait l'unicité au niveau de
-- l'administrateur, avec une définition de « vivante » que rien ne pouvait
-- jamais rendre fausse :
--
--     WHERE state = 'ACTIVE' AND private_destroyed_at IS NULL
--
--   · `state` ne recule pas — `key_guard` refuse ACTIVE → PENDING (AD021), et
--     il n'existe aucun état au-delà d'ACTIVE ;
--   · `private_destroyed_at` n'était posé par personne. Le balayage annoncé par
--     le commentaire de `destroyable_key` — « the rotation path reads this,
--     destroys each reference, then posts private_destroyed_at » — n'existait
--     pas. Il n'y avait qu'un GRANT sur la colonne, et aucun appelant.
--
-- Donc la phrase se lisait, en fait : au plus une clé par administrateur et par
-- usage, À JAMAIS. La première connexion passait, la seconde était refusée en
-- 23505, et attendre n'y changeait rien puisque le prédicat ne porte aucune
-- horloge. Une base, une connexion.
--
--
-- ═══ DEUX DÉFINITIONS CONCURRENTES D'UNE CLÉ VIVANTE ═══
--
-- `a_key_dies_with_its_session` a tranché : la vie utile d'une clé est bornée
-- par sa SESSION et pas seulement par son horloge — « une déconnexion n'est pas
-- une horloge ». `signing_key` a gagné son `JOIN … s.ended_at IS NULL`, et la
-- garde de `signed_command` relit `ended_at`.
--
-- L'index n'a jamais appris cette décision. Le schéma portait donc deux
-- définitions d'une clé vivante : celle de la vue, à trois bornes dont la
-- session, et celle de l'index, à deux bornes dont aucune ne tombe jamais.
-- C'est l'index qui refusait la connexion.
--
--
-- ═══ L'INVARIANT SE DÉPLACE, IL NE DISPARAÎT PAS ═══
--
-- Même geste que `a_key_has_one_purpose`, un cran plus bas : l'unicité passe de
-- l'administrateur à la SESSION. Ce qui compte survit par composition, et reste
-- tenu par le moteur des deux côtés :
--
--     une clé vivante par session et par usage      (cet index)
--   × une session non close par administrateur       (uq_session_mono)
--   ─────────────────────────────────────────────────────────────────
--   = au plus une clé SIGNANTE par administrateur et par usage
--
-- La conclusion tient parce que `signing_key` écarte les clés dont la session
-- est fermée : deux lignes signantes pour un même administrateur exigeraient
-- deux sessions non closes, ce que `uq_session_mono` refuse. Et elle s'obtient
-- sans mettre `now()` dans un index, qui est précisément ce que le schéma
-- initial expliquait ne pas pouvoir faire.
--
-- Deux connexions concurrentes ne laissent toujours pas deux clés derrière
-- elles : elles se heurtent une étape plus tôt, sur la session.
--
--
-- ═══ CE QU'ON ABANDONNE, ET POURQUOI CE N'EST PAS UNE PERTE ═══
--
-- L'énoncé littéral « un administrateur n'a qu'une ligne ACTIVE non détruite
-- dans toute la table » disparaît. Il confondait « ligne encore ACTIVE » et
-- « clé encore capable de signer », et une table en append-only est faite pour
-- accumuler : l'historique des clés est une trace, pas un état.
--
-- Reste que le matériel privé, lui, doit finir par tomber. C'est le travail du
-- balayage sur `destroyable_key`, qui existe désormais côté application.
--
--
-- ═══ signing_material RATTRAPE LA BORNE QUI LUI MANQUAIT ═══
--
-- Son commentaire affirme « Same predicate as signing_key ». Ça a cessé d'être
-- vrai avec `a_key_dies_with_its_session`, qui a posé la borne de session sur
-- `signing_key` et sur la garde des commandes, et l'a oubliée ici.
--
-- Ce n'est pas une vue quelconque : c'est LA voie de lecture de `kms_ref`, donc
-- de quoi signer. Laisser la référence privée d'une clé dont la session est
-- fermée être servie pendant le reliquat de l'heure, c'est exactement le défaut
-- que cette migration voulait fermer, laissé ouvert dans la vue qui distribue
-- le matériel. Personne ne la lisait encore — l'application garde `kms_ref` en
-- mémoire depuis la frappe — donc le défaut était dormant, et il se corrige
-- avant d'avoir un lecteur.
--
-- `destroyable_key` n'est pas touchée, pour la raison que
-- `a_key_dies_with_its_session` donne déjà : ce qui autorise à détruire un
-- privé, c'est la fin de la fenêtre de signature, et la vérification n'en
-- souffre pas puisqu'elle ne lit que `public_jwk`, qui reste.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. La seconde clé vivante d'une même session et d'un même
--   usage reste refusée par un 23505 standard — mais le fait nommé change :
--   avant « cet administrateur a déjà une clé », désormais « cette session a
--   déjà une clé de cet usage ».
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

DROP INDEX akeys.uq_key_one_active_per_purpose;

CREATE UNIQUE INDEX uq_key_one_active_per_session_purpose
  ON akeys.key (session_id, purpose)
  WHERE state = 'ACTIVE' AND private_destroyed_at IS NULL;

COMMENT ON INDEX akeys.uq_key_one_active_per_session_purpose IS
'Au plus une clé vivante par session et par usage. Croisé avec uq_session_mono,
qui n''admet qu''une session non close par administrateur, il donne au plus une
clé SIGNANTE par administrateur et par usage — puisque signing_key écarte les
clés dont la session est fermée. Deux index, une garantie, et pas de now() dans
un catalogue.';

-- La borne de session, oubliée ici quand signing_key l'a reçue. Les colonnes ne
-- changent pas, donc CREATE OR REPLACE suffit et les droits sont conservés.
CREATE OR REPLACE VIEW akeys.signing_material AS
  SELECT k.id, k.kid, k.user_id, k.kms_ref, k.signs_until, k.purpose
    FROM akeys.key AS k
    INNER JOIN admin.session AS s ON k.session_id = s.id
   WHERE k.state = 'ACTIVE'
     AND k.private_destroyed_at IS NULL
     AND now() < k.signs_until
     AND s.ended_at IS NULL;

COMMENT ON VIEW akeys.signing_material IS
'COMMENT signer. La seule voie de lecture de kms_ref — le SELECT sur cette
colonne est révoqué au niveau de la table. Même prédicat que signing_key, la
session comprise : la référence privée d''une clé dont la session est fermée est
inatteignable, comme la clé elle-même a cessé de pouvoir signer. Avec
destroyable_key, kms_ref est lisible exactement deux fois dans la vie d''une
clé — pendant qu''elle signe, et pendant qu''on la détruit.';

RESET ROLE;

-- Down Migration

--
-- ⚠ L'annulation n'est possible que si AUCUN administrateur ne détient deux clés
-- vivantes d'un même usage : l'index par administrateur n'en admet qu'une, et sa
-- recréation échoue en 23505 sinon. Retirer d'abord les clés surnuméraires — en
-- posant leur `private_destroyed_at`, puisque `akeys.key` est en append-only, et
-- après avoir détruit le matériel correspondant dans le KMS. Ce n'est pas un
-- défaut de cette migration : c'est l'invariant qu'elle desserre, qui se
-- resserre.

SET ROLE admin_owner;

CREATE OR REPLACE VIEW akeys.signing_material AS
  SELECT id, kid, user_id, kms_ref, signs_until, purpose
  FROM akeys.key
  WHERE state = 'ACTIVE'
    AND private_destroyed_at IS NULL
    AND now() < signs_until;

COMMENT ON VIEW akeys.signing_material IS
  'HOW to sign. The single readable path to kms_ref — SELECT on that column is revoked at table level. Same predicate as signing_key: the KMS reference of a destroyed or expired key is unreachable, so a compromised connection cannot walk the key history looking for material that outlived its window.';

DROP INDEX akeys.uq_key_one_active_per_session_purpose;

CREATE UNIQUE INDEX uq_key_one_active_per_purpose
  ON akeys.key (user_id, purpose)
  WHERE state = 'ACTIVE' AND private_destroyed_at IS NULL;

COMMENT ON INDEX akeys.uq_key_one_active_per_purpose IS
  'Au plus une clé vivante par administrateur et par usage, garantie par le moteur. Deux connexions concurrentes ne peuvent pas laisser deux clés de commande derrière elles.';

RESET ROLE;
