-- Up Migration

-- SEUL LE DÉNOUEMENT D'UNE DEMANDE S'ÉCRIT.
--
-- ═══ UNE FILE D'ATTENTE SANS SORTIE ═══
--
-- `an_approval_is_not_a_request` a ouvert l'inscription d'une demande et n'a
-- accordé AUCUN `UPDATE` — délibérément : « l'approbation viendra, et elle aura
-- sa propre autorisation, sur ses propres colonnes, le jour où la route
-- qui la porte existera. Accorder maintenant ce que rien n'appelle est
-- précisément ce que ce dépôt paie cher. »
--
-- Ce jour est celui-ci. En attendant, une demande pouvait naître et rien ne
-- pouvait la dénouer — et le commentaire de `withdrawn_at` dit exactement ce que
-- ça produit : « une file d'attente sans sortie devient l'endroit où les
-- décisions vont mourir, et où l'on finit par contourner la règle plutôt que de
-- l'appliquer ».
--
-- ═══ TROIS COLONNES, ET RIEN D'AUTRE ═══
--
--     approved_at, approved_by, approval_command_id
--
-- `request_is_a_fact` refuse déjà qu'autre chose bouge (AD089) : « a request is
-- a fact: only its outcome may be written — Approving something other than what
-- was asked is how a second pair of eyes stops meaning anything. »
--
-- Le privilège dit donc la même chose que le déclencheur, et c'est voulu. Il
-- parle AVANT lui, et il parle mieux : `42501` nomme ce qu'on n'a pas le droit
-- d'écrire, là où `AD089` décrit une incohérence qu'on pourrait croire réparable
-- en changeant les valeurs. Deux gardes pour un invariant qui, s'il tombe, fait
-- tomber la promesse entière — « approuvée par un tiers, trois personnes
-- distinctes ».
--
-- ═══ CE QUI N'EST TOUJOURS PAS ACCORDÉ ═══
--
-- `withdrawn_at` et `withdrawn_by`. Retirer sa demande est un troisième acte,
-- avec sa propre route et sa propre commande signée. Même raison qu'au tour
-- précédent : ce que rien n'appelle ne s'accorde pas.
--
-- Et toujours aucune suppression : `authority_request_no_delete` refuse,
-- l'ajout seul est la règle, et une demande retirée du registre serait une
-- décision dont plus rien ne dit qu'elle a eu lieu.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau.
--
--   Les codes qu'elle rend ATTEIGNABLES, faute d'un chemin pour les déclencher :
--     AD089  la demande est déjà dénouée, ou l'approbation porte sur autre chose
--            que ce qui a été demandé
--     AD087  l'approbation ne cite pas une commande `authority.approve` de cet
--            approbateur
--     23514  authority_request_approver_is_a_third — l'approbateur est le
--            demandeur ou le sujet
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- COLONNE PAR COLONNE, comme l'INSERT. Un `GRANT UPDATE` de table couvrirait
-- `subject_user_id` et `reason` : approuver deviendrait alors le moment où l'on
-- peut réécrire ce qu'on approuve, et le second regard cesserait de porter sur
-- ce que le premier a demandé.
GRANT UPDATE (approved_at, approved_by, approval_command_id)
    ON api.authority_request TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

REVOKE UPDATE (approved_at, approved_by, approval_command_id)
    ON api.authority_request FROM app_admin_plane;

RESET ROLE;
