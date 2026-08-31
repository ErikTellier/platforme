-- Up Migration

-- UNE HEURE ÉTAIT UNE PROMESSE, PAS UNE BORNE.
--
-- `absolute_expires_at` porte ce commentaire depuis le premier jour :
--
--     'HARD ceiling = created_at + 1 h. The refresh path refuses past it
--      (AD010), regardless of activity.'
--
-- Il se lit comme une garantie. Il n'en était pas une. Le seul contrôle sur la
-- colonne est `session_absolute_after_creation`, qui exige que l'échéance suive
-- la création — et rien de plus. `session_emission_guard` ne regarde que
-- l'activité de l'administrateur. Une session de dix ans passait.
--
-- Personne n'en aurait ouvert : l'unique écrivain est l'application, et sa
-- requête fixe l'heure. Mais « personne ne le fait aujourd'hui » est une
-- propriété du code appelant, pas du schéma. Le jour où une seconde requête
-- écrit dans cette table — un chemin d'usurpation, un outil d'exploitation, un
-- test mal isolé — plus rien ne la retient.
--
-- C'est exactement ce que dit l'en-tête de l'anneau d'audit à propos de la
-- rétention : « Une obligation écrite dans un contrat n'est pas un mécanisme ».
-- La même phrase valait ici, et la contrainte manquait.
--
--
-- ═══ POURQUOI UN CHECK ET PAS UN CLAMP DANS LE GARDE ═══
--
-- Un déclencheur pourrait ramener l'échéance au plafond silencieusement. Il
-- rendrait la faute invisible : l'appelant demanderait deux heures, en
-- obtiendrait une, et ne le saurait jamais.
--
-- Un CHECK refuse. Il apparaît dans le catalogue, se lit sans ouvrir de
-- fonction, et un contrôle de conformité peut l'interroger. C'est la forme que
-- prend un invariant qu'on veut prouvable.
--
--
-- ═══ POURQUOI `<=` ET NON `=` ═══
--
-- Une session PLUS COURTE reste légitime : une élévation temporaire, une
-- fenêtre d'astreinte, un environnement qui veut serrer. Ce qu'on interdit,
-- c'est de dépasser. Et `now()` étant stable dans une transaction, la valeur
-- par défaut de `created_at` et l'expression de l'appelant coïncident à la
-- microseconde — l'égalité passe sans marge de tolérance à inventer.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   STANDARD codes, enforced by constraints:
--     23514  check_violation — une session au-delà d'une heure
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

ALTER TABLE admin.session
  ADD CONSTRAINT session_ceiling_bounded
  CHECK (absolute_expires_at <= created_at + interval '1 hour');

COMMENT ON CONSTRAINT session_ceiling_bounded ON admin.session IS
  'Le plafond d''une heure, tenu par le moteur et non par le commentaire. Plus court est permis — une fenêtre restreinte reste une décision légitime ; plus long ne l''est pas.';

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

ALTER TABLE admin.session DROP CONSTRAINT session_ceiling_bounded;

RESET ROLE;
