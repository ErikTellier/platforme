-- Up Migration

-- LE PREMIER ADMINISTRATEUR NE PEUT PAS SE DÉCLARER LUI-MÊME.
--
-- `admin."user"` porte ce commentaire depuis le premier jour : « an admin is
-- explicitly declared, never self-created ». C'est la propriété qui fait qu'une
-- connexion réussie chez Entra ne vaut pas une entrée dans le plan
-- d'administration — appartenir à l'annuaire et pouvoir reconfigurer la
-- plateforme sont deux choses, et rien dans le flux OIDC ne les distingue.
--
-- Mais elle produit un amorçage impossible : personne ne peut entrer tant que
-- personne n'est déclaré, et il n'existe aucun chemin applicatif pour déclarer
-- le premier. Cette migration est ce chemin, et elle n'existe que pour lui.
--
--
-- ═══ L'OID, ET PAS L'UPN ═══
--
-- `admin.identity` accepte deux formes : une identité liée, portant l'`oid`, ou
-- une identité en attente, portant un `provision_key` que la première connexion
-- viendra apparier. La seconde était pensée pour un administrateur qu'on déclare
-- sans connaître son identifiant d'annuaire.
--
-- Ce produit ne se trouve jamais dans ce cas. Les administrateurs suivants sont
-- invités par l'API Graph, qui rend l'identifiant d'objet dans la réponse : on
-- le connaît AVANT que l'intéressé ne se connecte. Et pour le premier, il se lit
-- dans son propre jeton.
--
-- Poser l'`oid` directement évite deux choses :
--
--   · L'AMBIGUÏTÉ DE L'UPN. Pour un invité, Entra réécrit l'UPN interne
--     (`quelquun_gmail.com#EXT#@tenant.onmicrosoft.com`) alors que le jeton
--     porte l'adresse d'origine dans `preferred_username`. Deux valeurs, et
--     celle qu'on sème doit être exactement celle qu'on comparera.
--
--   · UNE DONNÉE PERSONNELLE ÉPHÉMÈRE. `provision_key` est décrit comme telle
--     dans son propre commentaire, effacée à la capture. Ne jamais l'écrire vaut
--     mieux que l'écrire puis l'effacer.
--
-- Le déclencheur `identity_bind_once` estampille `bound_at` à l'insertion — sa
-- branche INSERT existe précisément pour ce cas. L'identité naît liée, et le
-- même déclencheur interdit ensuite de la relier ailleurs (AD050).
--
--
-- ═══ LA VALEUR VIENT DE L'ENVIRONNEMENT, PAS DU FICHIER ═══
--
-- Un `oid` écrit en dur ici coûterait cher. Il n'a de sens que dans UN annuaire :
-- rejoué contre un autre tenant, il crée un administrateur fantôme qui ne se
-- connectera jamais. Et corriger le fichier avant un déploiement — la seule
-- issue — laisse la base de développement et le fichier dire deux choses
-- différentes, sans que rien ne le signale : les outils de migration ne
-- comparent que des numéros de version.
--
-- La valeur est donc lue dans un réglage de session, posé par le script de
-- migration depuis `BOOTSTRAP_ADMIN_OID`. Un fichier, une version, et chaque
-- environnement sème le sien — ce qui vaut aussi pour un développeur qui veut
-- ouvrir le plan avec son propre compte.
--
-- Le schéma lit déjà des réglages ailleurs : `audit.event` résout le client par
-- `current_setting`. Ce n'est pas un motif importé.
--
--
-- ═══ CE QU'ELLE NE FAIT PAS ═══
--
-- Elle ne sème QU'UNE FOIS, et qu'un seul administrateur. Les suivants passent
-- par l'invitation Graph et l'écriture applicative : c'est le chemin normal, et
-- il doit rester le seul. Une migration qui déclarerait des administrateurs au
-- fil de l'eau ferait du dépôt le registre des personnes.
--
-- Elle ne se défait pas non plus. `no_delete_user` et `no_delete_identity`
-- interdisent la suppression, et pour cause : les commandes signées et le
-- journal d'audit référencent cet identifiant. La migration inverse ne peut donc
-- rien retirer, et le dire vaut mieux que de la laisser croire réversible.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   RAISED by this migration (custom SQLSTATE):
--     AD120  aucun administrateur d'amorçage n'est déclaré
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

DO $$
DECLARE
  v_oid  text := nullif(current_setting('app.bootstrap_admin_oid', true), '');
  v_user uuid;
BEGIN
  IF v_oid IS NULL THEN
    RAISE EXCEPTION 'aucun administrateur d''amorçage n''est déclaré'
      USING ERRCODE = 'AD120',
            HINT = 'Poser BOOTSTRAP_ADMIN_OID : c''est le claim oid du compte Entra qui doit pouvoir ouvrir le plan d''administration. Il se lit dans le jeton de ce compte, ou dans invitedUser.id si Graph l''a invité.';
  END IF;

  -- Idempotence par l'identité et non par l'utilisateur : c'est l'oid qui
  -- désigne quelqu'un, l'utilisateur n'étant qu'un identifiant interne.
  IF EXISTS (
    SELECT FROM admin.identity
     WHERE provider = 'ENTRA' AND provider_id = v_oid
  ) THEN
    RETURN;
  END IF;

  INSERT INTO admin."user" DEFAULT VALUES RETURNING id INTO v_user;

  -- bound_at est estampillé par identity_bind_once, jamais fourni ici.
  INSERT INTO admin.identity (user_id, provider, provider_id)
  VALUES (v_user, 'ENTRA', v_oid);

  RAISE NOTICE 'administrateur d''amorçage déclaré pour l''oid %', v_oid;
END $$;

RESET ROLE;

-- Down Migration

-- Rien. `no_delete_user` et `no_delete_identity` interdisent la suppression, et
-- c'est voulu : les commandes signées et le journal d'audit référencent cet
-- identifiant. Retirer l'administrateur d'amorçage reviendrait à effacer
-- l'auteur d'actes déjà commis. Désactiver son compte est en revanche possible
-- à tout moment, par `deactivated_at`, ce qui est une décision d'exploitation et
-- non une annulation de migration.
SELECT 1;
