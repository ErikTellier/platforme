-- Up Migration

-- DEUX TABLES SORTAIENT DU PÉRIMÈTRE D'AUDIT SANS QUE PERSONNE NE L'AIT DÉCIDÉ.
--
-- La règle est simple et ancienne : toute table est surveillée, ou bien elle est
-- ARGUMENTÉE. `admin.login_flow` et `admin.spent_proof` n'étaient ni l'un ni
-- l'autre — elles étaient simplement absentes d'`audit.watched`, ce qui se lit
-- « on a oublié » aussi bien que « on a choisi ». `spent_proof` est de moi, et je
-- ne me suis pas posé la question en l'écrivant.
--
-- Cette migration tranche les deux, dans les deux sens.
--
--
-- ═══ `login_flow` EST SURVEILLÉE ═══
--
-- Elle porte le seul enregistrement qu'une authentification a été TENTÉE : quand,
-- vers où l'on revenait, avec quelle empreinte de navigateur, et si le flux a été
-- consommé ou abandonné. C'est exactement ce qu'on relit après un incident, et
-- c'est perdu à jamais autrement — la table est purgée au bout d'un jour.
--
-- Le volume ne s'y oppose pas : une ligne par connexion, sur un plan qui sert
-- deux ou trois personnes.
--
-- CE QUI EST EXPURGÉ. `auditable_column` est une liste BLANCHE : ce qui n'y
-- figure pas est remplacé par `{"redacted": true}`. Trois colonnes en sont donc
-- tenues à l'écart :
--
--   · `code_verifier` — le secret PKCE. Écrit dans le journal, il permettrait
--     d'échanger un code d'autorisation intercepté ;
--   · `nonce` — ce qui lie le jeton d'identité à CE flux ;
--   · `state` — le jeton anti-rejeu du flux. Il voyage dans l'URL, donc il est
--     moins secret que les deux autres ; il reste inutile au journal, et
--     `id` identifie déjà la ligne.
--
-- `cnf_jkt` est gardé EN CLAIR, comme sur `admin.session` où il l'est déjà :
-- c'est le condensat d'une clé publique, et savoir quel navigateur a ouvert un
-- flux est précisément l'intérêt de la chose.
--
--
-- ═══ `spent_proof` EST HORS PÉRIMÈTRE, ET LE DIT ═══
--
-- Ce n'est pas un registre, c'est un CACHE. Elle existe pour qu'une preuve DPoP
-- ne serve pas deux fois, elle porte un `jti` et une échéance, et elle est vidée
-- par sa propre expiration — c'est d'ailleurs pourquoi elle ne figure pas non
-- plus dans `admin.retention`, qui déclare ce qu'on GARDE.
--
-- L'auditer coûterait une écriture d'audit PAR REQUÊTE AUTHENTIFIÉE, pour
-- apprendre ce que le journal d'accès dit déjà mieux. Et le journal d'audit
-- deviendrait dominé, en volume, par la table qui a le moins à raconter.
--
-- Le refus est donc écrit dans le commentaire de la table, là où on le lit
-- avant de se demander pourquoi elle manque.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. `audit.watch` lève XA011 si une colonne déclarée
--   auditable n'existe pas — une faute de frappe y expurgerait en silence la
--   colonne qu'on voulait justement voir.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

SELECT audit.watch('admin', 'login_flow',
  ARRAY['id', 'redirect_to', 'cnf_jkt',
        'created_at', 'expires_at', 'consumed_at']::name[],
  'all');

COMMENT ON TABLE admin.spent_proof IS
'Les preuves DPoP déjà dépensées, pour qu''aucune ne serve deux fois.

HORS DU PÉRIMÈTRE D''AUDIT, DÉLIBÉRÉMENT. C''est un cache, pas un registre : une
ligne par requête authentifiée, vidée par sa propre échéance. L''auditer
coûterait une écriture d''audit par requête pour apprendre ce que le journal
d''accès dit déjà, et le journal d''audit finirait dominé par la table qui a le
moins à raconter.

Absente d''admin.retention pour la même raison : cette table déclare ce qu''on
GARDE, et un cache ne se garde pas — purge_spent_proofs le vide à l''échéance.';

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

UPDATE audit.watched SET removed_at = now()
 WHERE schema_name = 'admin' AND table_name = 'login_flow';

DROP TRIGGER IF EXISTS zz_audit ON admin.login_flow;
DROP TRIGGER IF EXISTS zz_audit_truncate ON admin.login_flow;

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name = 'login_flow';

COMMENT ON TABLE admin.spent_proof IS NULL;

RESET ROLE;
