-- Up Migration

-- UNE DEMANDE PÉRIMÉE NE S'APPROUVE PAS.
--
-- ═══ UNE GARANTIE QUI SE LISAIT VRAIE ═══
--
-- `authority_request.expires_at` existe depuis `four_eyes_are_two_acts`. Il
-- voyage jusqu'à l'octroi, où `grant_follows_a_request` le tient sérieusement :
-- « approuver trois jours et accorder dix, c'est approuver autre chose ».
--
-- Mais RIEN ne le regardait au moment d'approuver. Les six contraintes de la
-- table portent sur la cohérence — portée, dénouement unique, approbateur tiers
-- — et aucune ne le mentionne. `request_is_a_fact` ne contrôle que « déjà
-- dénouée » et l'immuabilité du reste.
--
-- Conséquence, mesurée avant d'écrire cette migration : une demande assortie
-- d'une échéance de trois jours pouvait être approuvée trois semaines plus tard.
-- Un champ nommé `expires_at` se lit comme une échéance opposable ; il n'en
-- était pas une. C'est la forme de défaut que ce schéma traque partout ailleurs
-- — une garantie qui se lit vraie — et elle était ici en toutes lettres dans un
-- nom de colonne.
--
-- ═══ SEULE L'APPROBATION EST CONCERNÉE ═══
--
-- Retirer une demande périmée reste possible, et c'est le geste normal de
-- ménage : `withdrawn_at` est la sortie de la file, et une file dont la sortie
-- se ferme est exactement ce que son commentaire décrit comme « l'endroit où les
-- décisions vont mourir ».
--
-- Ce qui devient impossible est de la DÉNOUER PAR OUI après son terme. Le second
-- regard doit porter sur une demande encore vivante, sans quoi il ratifie une
-- décision que son auteur avait bornée dans le temps.
--
-- ═══ `NEW.approved_at` ET NON `now()` ═══
--
-- La comparaison porte sur l'instant INSCRIT, pas sur l'horloge du moment. Les
-- deux coïncident sur le chemin normal — la requête pose `now()` — mais un
-- appelant qui daterait l'approbation lui-même serait jugé sur ce qu'il a écrit,
-- et non sur le hasard du temps de transaction. Le fait est ce qu'on relit ;
-- c'est donc le fait qu'on éprouve.
--
-- ═══ POURQUOI UN DÉCLENCHEUR ET NON UNE CONTRAINTE ═══
--
-- Une CHECK ne peut pas comparer `NEW` à `OLD`, et c'est bien la transition qui
-- compte : la ligne périmée existe légitimement, ce qui est refusé est de lui
-- ajouter une approbation. Un `CHECK (approved_at <= expires_at)` refuserait
-- aussi de la RETIRER, puisqu'il jugerait la ligne entière à chaque écriture.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   AD094  la demande a passé son terme : elle ne peut plus être approuvée.
--          Elle reste retirable.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE FUNCTION admin.request_expiry_is_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- On ne juge QUE l'instant où l'approbation se pose. Un retrait, une ligne
    -- déjà dénouée, une écriture qui ne touche pas l'approbation : rien de tout
    -- cela ne regarde cette garde, et `request_is_a_fact` dit déjà le reste.
    IF NEW.approved_at IS NULL OR OLD.approved_at IS NOT NULL THEN
        RETURN NEW;
    END IF;

    -- Sans échéance, la demande attend aussi longtemps qu'il le faut. C'est une
    -- demande légitime, et `pending_request` la rend visible plutôt que de la
    -- refuser.
    IF OLD.expires_at IS NOT NULL AND NEW.approved_at > OLD.expires_at THEN
        RAISE EXCEPTION 'this request expired at %, it may no longer be approved',
            OLD.expires_at
            USING ERRCODE = 'AD094',
                  HINT = 'A deadline nobody enforces is not a deadline. The '
                         'request may still be withdrawn.';
    END IF;

    RETURN NEW;
END;
$$;

-- LES FONCTIONS NAISSENT EXÉCUTABLES PAR PUBLIC, et
-- `a_default_acl_is_an_open_door` a payé ce défaut trois fois. Le retrait est
-- immédiat, pas remis à un balayage ponctuel qui ne repassera pas.
REVOKE EXECUTE ON FUNCTION admin.request_expiry_is_binding() FROM PUBLIC;

COMMENT ON FUNCTION admin.request_expiry_is_binding() IS
'Refuse d''approuver une demande après son terme (AD094). Le retrait reste
ouvert : une file d''attente dont la sortie se ferme devient l''endroit où les
décisions vont mourir. La comparaison porte sur `approved_at` inscrit, pas sur
`now()` — on juge le fait qu''on relira.';

-- LE NOM COMMENCE PAR `zz` POUR PASSER EN DERNIER. Postgres déclenche les
-- `BEFORE` par ordre alphabétique, et une demande à la fois DÉNOUÉE et PÉRIMÉE
-- doit répondre AD089 — « déjà dénouée » — qui décrit la vraie faute. Sans ce
-- préfixe, `request_expiry_is_binding` passerait avant
-- `authority_request_is_a_fact` et accuserait le terme là où le problème est
-- qu'on redénoue.
--
-- Vérifié sur la base : les trois autres `BEFORE` s'appellent
-- `authority_request_*`, et celui-ci vient bien après eux.
CREATE TRIGGER zz_request_expiry_is_binding
    BEFORE UPDATE ON admin.authority_request
    FOR EACH ROW EXECUTE FUNCTION admin.request_expiry_is_binding();

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DROP TRIGGER zz_request_expiry_is_binding ON admin.authority_request;
DROP FUNCTION admin.request_expiry_is_binding();

RESET ROLE;
