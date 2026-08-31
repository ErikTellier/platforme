-- Up Migration

-- LE PLAN PEUT ÉMETTRE UNE COMMANDE, JAMAIS LA DATER NI LA NOMMER.
--
-- ═══ LA TABLE CENTRALE DU PLAN N'AVAIT AUCUNE PORTE ═══
--
-- `admin.signed_command` est ce pour quoi ce service existe : la commande qu'un
-- administrateur signe de SA clé, qu'un service souverain vérifie de son côté, et
-- qui fonde la non-répudiation individuelle.
--
-- Elle n'a jamais eu de vue `api`. Trente-et-une vues exposent les sessions, les
-- clés, les défis, les tickets — pas celle-là. Le service ne pouvait donc ni lire
-- ni écrire le geste central du plan, et la doctrine « le service lit par api,
-- jamais les tables » ne lui laissait aucun autre chemin. Ce n'était pas un
-- refus : c'était une absence, et elle se lisait comme une interdiction.
--
-- ═══ CE QUE LA VUE PORTE, ET CE QU'ELLE N'ACCORDE PAS ═══
--
-- `only_a_touch_consumes_a_challenge` a écrit la règle et la raison :
--
--     « GRANT INSERT ON api.challenge est accordé AU NIVEAU DE LA TABLE, donc
--       sur toutes ses colonnes. […] On ne retire pas une colonne d'un privilège
--       accordé au niveau de la table. REVOKE INSERT (col) ne fait rien d'utile :
--       le privilège de table subsiste et continue de couvrir la colonne.
--       PostgreSQL n'échoue pas, il ne retire simplement rien — le pire des deux,
--       puisque la migration paraît avoir réussi. »
--
-- L'INSERT est donc accordé COLONNE PAR COLONNE dès le premier jour, et ce qui
-- n'est pas nommé n'est pas écrit :
--
--   `id`         a un défaut. L'accorder n'ajoute que la possibilité de le
--                contredire — et un identifiant choisi par l'appelant est un
--                identifiant qu'on peut faire collisionner.
--   `issued_at`  a un défaut, et c'est le plus important des deux. Un plan qui
--                peut dater sa propre commande peut ANTIDATER : produire
--                aujourd'hui une commande qui prétend avoir été signée pendant
--                la fenêtre d'une clé morte, donc encore vérifiable au JWKS.
--                L'horodatage d'une commande signée est une preuve ; il
--                appartient à la base.
--   `batch_seq`  est le rang dans un lot, et `one_touch_one_batch` le dérive.
--                Le poser à la main permettrait deux commandes au même rang, ou
--                un lot qui se croit complet.
--
-- Ni UPDATE ni DELETE, et ce n'est pas une omission : `command_is_immutable`
-- refuse déjà la première, l'ajout seul refuse la seconde. Les accorder ne
-- donnerait qu'un second chemin vers un refus qui existe.
--
-- ═══ POURQUOI `security_invoker` ═══
--
-- `admin.signed_command` porte une sécurité de ligne FORCÉE — le propriétaire y
-- est soumis comme les autres. Sans `security_invoker`, la vue s'exécuterait sous
-- l'identité de SON propriétaire, et `tenant_visible` — qui appelle
-- `admin.may_read(target_tenant_id)` — jugerait pour quelqu'un d'autre que
-- l'appelant. C'est la forme retenue partout ailleurs dans ce schéma pour la même
-- raison.
--
-- La conséquence est nette : lire ou écrire ici EXIGE un opérateur lié. Sans lui
-- `admin.app_admin()` lève AD100, comme il doit.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Elle expose une table et borne ce qu'on peut y écrire.
--
--   Les codes qu'elle rend ATTEIGNABLES, faute d'un chemin pour les déclencher :
--     AD081  le défi cité n'a jamais été consommé
--     AD080  la commande ne correspond pas à la présence prouvée
--     AD100  aucun administrateur n'est lié à cette session
--     23505  uq_command_digest — rejeu ; uq_command_challenge — deux commandes
--            pour une seule touche
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE VIEW api.signed_command
    WITH (security_invoker = TRUE)
AS
SELECT id, user_id, session_id, key_id, challenge_id,
       action, scope, target_tenant_id, command_digest,
       issued_at, batch_id, batch_seq
  FROM admin.signed_command;

COMMENT ON VIEW api.signed_command IS
'Les commandes signées, telles que le plan peut les voir et les poser. Il peut en
ÉMETTRE une — le signataire, sa session, sa clé, le défi qu''il a consommé,
l''action, la portée, la cible et l''empreinte — et jamais décider ni QUAND elle a
été émise ni SOUS QUEL identifiant : `issued_at` et `id` ne sont pas accordés à
l''écriture. Antidater une commande la ferait retomber dans la fenêtre d''une clé
morte, donc encore publiée au JWKS ; c''est la base qui date.';

GRANT SELECT ON api.signed_command TO app_admin_plane;

-- COLONNE PAR COLONNE, ET DÈS LE DÉPART. Un GRANT de table serait irréversible
-- au niveau de la colonne, et il faudrait le révoquer en entier pour le refaire.
GRANT INSERT (user_id, session_id, key_id, challenge_id,
              action, scope, target_tenant_id, command_digest, batch_id)
    ON api.signed_command TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP VIEW api.signed_command;

RESET ROLE;
