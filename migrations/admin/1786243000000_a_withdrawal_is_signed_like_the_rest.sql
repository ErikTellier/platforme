-- Up Migration

-- UN RETRAIT SE SIGNE, COMME LE RESTE.
--
-- ═══ LA SORTIE ANNONCÉE QUI N'EXISTAIT PAS ═══
--
-- Deux migrations ont promis ce geste, dans les mêmes termes :
--
--     « Retirer sa demande est un troisième acte, avec sa propre route et sa
--       propre commande signée. » — an_approval_is_not_a_request
--     « `withdrawn_at` et `withdrawn_by`. Retirer sa demande est un troisième
--       acte, avec sa propre route et sa propre commande signée. »
--       — only_the_outcome_of_a_request_is_written
--
-- Et `an_expired_request_is_not_approved` en fait le geste NORMAL : une demande
-- périmée ne s'approuve plus, elle se retire — « une file dont la sortie se
-- ferme est exactement l'endroit où les décisions vont mourir ».
--
-- Or il n'y avait ni route, ni commande, ni **colonne pour la citer**. Les deux
-- colonnes existantes disent QUAND et PAR QUI, jamais SUR QUELLE PREUVE :
-- `authority_request_withdrawal_complete` ne les apparie qu'entre elles. Un
-- retrait était donc, seul de la table, un acte que personne ne pouvait
-- rattacher à une touche matérielle.
--
-- ═══ CE QUE ÇA COÛTAIT ═══
--
-- Retirer une demande n'accorde rien — c'est ce qui rend l'oubli facile à
-- commettre et coûteux à garder. Mais ANNULER la demande d'un autre est une
-- décision : elle éteint une autorité qu'on s'apprêtait à accorder, et six mois
-- plus tard « qui a annulé l'astreinte du 3 mars, et depuis quel poste » est une
-- question qu'on pose. `request_is_signed` répondait pour la demande (AD088) et
-- pour l'approbation (AD088) ; sur le retrait, il n'avait rien à dire.
--
-- ═══ QUI PEUT RETIRER : LA QUESTION N'EST PAS TRANCHÉE ICI, ET C'EST VOULU ═══
--
-- Cette migration exige que le retrait soit SIGNÉ PAR CELUI QUI EST NOMMÉ comme
-- retirant — la même égalité que pour les deux autres actes, et la seule qui
-- fonde la non-répudiation. Elle n'exige PAS que ce soit le demandeur.
--
-- Le vocabulaire des deux migrations dit « sa demande », ce qui suggère le
-- demandeur. Mais « le geste normal de ménage » sur une file périmée suggère le
-- contraire — celui qui part n'est plus là pour ranger derrière lui. Les deux
-- lectures sont défendables, et poser la mauvaise en contrainte coûterait une
-- migration pour la défaire.
--
-- Ce qui reste vrai dans les deux cas : le retrait est tracé, signé, et
-- l'ajout seul empêche de l'effacer. Un retrait abusif se voit ; c'est ce qui
-- permet d'attendre de savoir laquelle des deux règles on veut.
--
-- ═══ UNE CONTRAINTE DE PLUS, PAS UNE CONTRAINTE MODIFIÉE ═══
--
-- `authority_request_withdrawal_complete` reste telle quelle et
-- `authority_request_withdrawal_is_signed` s'ajoute à côté. On aurait pu
-- l'élargir — il aurait fallu la retirer puis la reposer, donc rendre le schéma
-- momentanément sans elle, et faire porter à une seule contrainte deux
-- invariants dont un test ne saurait plus dire lequel a parlé. Deux noms, deux
-- messages, `db.Contrainte` les distingue.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   AD088  (étendu) la commande de retrait n'est pas ce retrait, par son auteur
--   23514  `authority_request_withdrawal_is_signed` : retiré sans commande, ou
--          commande sans retrait
--   23503  `authority_request_withdrawal_command_fk` : la commande citée
--          n'existe pas
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- ON CONFLICT : même raison qu'à `four_eyes_are_two_acts` — la descente ne
-- retire pas un code encore référencé, donc la remontée peut le retrouver.
INSERT INTO admin.command_action (code, description, applies_to) VALUES
  ('authority.withdraw', 'Retirer une demande d''autorité avant son dénouement.', 'ANY')
ON CONFLICT (code) DO NOTHING;

ALTER TABLE admin.authority_request
    ADD COLUMN withdrawal_command_id uuid;

ALTER TABLE admin.authority_request
    ADD CONSTRAINT authority_request_withdrawal_command_fk
        FOREIGN KEY (withdrawal_command_id)
        REFERENCES admin.signed_command (id) ON DELETE RESTRICT;

ALTER TABLE admin.authority_request
    ADD CONSTRAINT authority_request_withdrawal_is_signed CHECK (
        (withdrawn_at IS NULL) = (withdrawal_command_id IS NULL));

COMMENT ON COLUMN admin.authority_request.withdrawal_command_id IS
'La commande signée qui a retiré cette demande. Sans elle, un retrait disait
QUAND et PAR QUI, jamais sur quelle preuve — seul acte de cette table qu''on ne
pouvait rattacher à aucune touche matérielle.

Retirer n''accorde rien, et c''est ce qui rend l''oubli facile à commettre. Mais
annuler la demande d''un autre éteint une autorité qu''on s''apprêtait à
accorder, et « qui a annulé l''astreinte du 3 mars » est une question qui se
pose des mois plus tard.';

-- ═══ LE DÉCLENCHEUR APPREND LE TROISIÈME ACTE ═══
--
-- Corps recomposé en entier : les deux premiers blocs sont inchangés, le
-- troisième est neuf. Une fonction ne se modifie pas par morceaux.

CREATE OR REPLACE FUNCTION admin.request_is_signed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    PERFORM FROM admin.signed_command c
     WHERE c.id = NEW.request_command_id
       AND c.action = 'authority.request'
       AND c.scope = NEW.scope
       AND c.target_tenant_id IS NOT DISTINCT FROM NEW.tenant_id
       AND c.user_id = NEW.requested_by;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the request command is not this request, by %',
            NEW.requested_by
            USING ERRCODE = 'AD088',
                  HINT = 'A request is signed by whoever asks. Recycling '
                         'someone else''s command is what this refuses.';
    END IF;

    IF NEW.approved_at IS NOT NULL THEN
        PERFORM FROM admin.signed_command c
         WHERE c.id = NEW.approval_command_id
           AND c.action = 'authority.approve'
           AND c.scope = NEW.scope
           AND c.target_tenant_id IS NOT DISTINCT FROM NEW.tenant_id
           AND c.user_id = NEW.approved_by;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'the approval command is not this approval, by %',
                NEW.approved_by
                USING ERRCODE = 'AD088',
                      HINT = 'THE WHOLE POINT: the approval is signed by the '
                             'APPROVER, with their own hardware key. Otherwise '
                             'four eyes is a column somebody typed.';
        END IF;
        -- L'approbateur doit détenir l'autorité sur ce périmètre, sinon un
        -- second regard serait celui de n'importe qui.
        IF NOT admin.signs_here(NEW.approved_by, NEW.tenant_id) THEN
            RAISE EXCEPTION 'the approver holds no authority over that perimeter'
                USING ERRCODE = 'AD088';
        END IF;
    END IF;

    -- LE RETRAIT, MÊME EXIGENCE QUE LES DEUX AUTRES. On ne vérifie PAS que
    -- l'auteur est le demandeur : voir l'entête, la règle n'est pas tranchée.
    -- Ce qui est tranché, c'est qu'il a touché sa clé et qu'on peut le lui
    -- opposer.
    IF NEW.withdrawn_at IS NOT NULL THEN
        PERFORM FROM admin.signed_command c
         WHERE c.id = NEW.withdrawal_command_id
           AND c.action = 'authority.withdraw'
           AND c.scope = NEW.scope
           AND c.target_tenant_id IS NOT DISTINCT FROM NEW.tenant_id
           AND c.user_id = NEW.withdrawn_by;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'the withdrawal command is not this withdrawal, by %',
                NEW.withdrawn_by
                USING ERRCODE = 'AD088',
                      HINT = 'Withdrawing cancels an authority someone was '
                             'about to hold. It is signed by whoever does it.';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

-- ═══ LA VUE APPREND LA COLONNE ═══
--
-- Une vue fige sa liste de colonnes à la création : ajouter la colonne à la
-- table ne l'y fait pas entrer. `CREATE OR REPLACE` ne sait qu'AJOUTER à la fin,
-- ce qui suffit ici et garantit qu'aucune position existante ne bouge.
-- `WITH` EST OBLIGATOIRE ICI, MEME EN REMPLACEMENT.
--
-- `CREATE OR REPLACE VIEW` REINITIALISE les options de la vue : l'omettre ne
-- « garde pas l'existant », il l'efface. La vue retombe alors en
-- `security_definer` implicite et s'execute avec les droits de son
-- proprietaire, `admin_owner` — a qui la politique `owner_is_the_vetted_path`
-- rend `true` sans condition. Le plan devient un `Seq Scan` SANS filtre, et
-- toutes les lignes de tous les clients remontent.
--
-- Constate en base, plan a l'appui : l'option avait disparu de trois vues.
CREATE OR REPLACE VIEW api.authority_request
    WITH (security_invoker = TRUE)
AS
SELECT id, scope, tenant_id, subject_user_id, reason, expires_at,
       requested_at, requested_by, request_command_id,
       approved_at, approved_by, approval_command_id,
       withdrawn_at, withdrawn_by, withdrawal_command_id
  FROM admin.authority_request;

-- LA VUE EST EN `security_invoker` : le privilège de la TABLE est donc exigé
-- aussi. `withdrawn_at` et `withdrawn_by` l'ont depuis `four_eyes_are_two_acts` ;
-- la colonne neuve ne l'a pas.
GRANT UPDATE (withdrawal_command_id) ON admin.authority_request TO app_admin_plane;

-- LES TROIS ENSEMBLE, ET RIEN D'AUTRE. `only_the_outcome_of_a_request_is_written`
-- a accordé les trois colonnes de l'approbation et refusé celles-ci en disant
-- « ce que rien n'appelle ne s'accorde pas ». La route existe maintenant.
GRANT UPDATE (withdrawn_at, withdrawn_by, withdrawal_command_id)
    ON api.authority_request TO app_admin_plane;

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

-- DÉTRUIRE PUIS RECRÉER, ET NON `CREATE OR REPLACE`.
--
-- `CREATE OR REPLACE VIEW` sait ajouter une colonne à la fin, jamais en
-- retirer : Postgres refuse avec « cannot drop columns from view ». Ce retour
-- en enlève une, il ne peut donc pas passer par là. Constaté en exécutant
-- `migrate:down` pour la première fois — ce retour n'avait jamais été joué.
--
-- ET `security_invoker` EST REPOSÉ EXPLICITEMENT. C'est `an_approval_is_not_a_request`
-- qui l'avait posé, et un `CREATE VIEW` nu ne l'hérite pas. Sans lui, la vue
-- s'exécute avec les droits de `admin_owner`, à qui la politique
-- `owner_is_the_vetted_path` rend `true` sans condition : le plan devient
-- `Seq Scan` SANS filtre, et toutes les lignes de tous les clients remontent.
-- Mesuré, plan à l'appui. C'est exactement ce que l'oubli du `WITH` dans la
-- montée de cette migration a provoqué en base.
--
-- ET L'ACL EST RENDUE. Un `DROP` emporte les droits avec l'objet ; il faut les
-- reposer colonne par colonne. `withdrawal_command_id` en est absent
-- volontairement : c'est la colonne que ce retour supprime.
DROP VIEW api.authority_request;

CREATE VIEW api.authority_request
    WITH (security_invoker = TRUE)
AS
SELECT id, scope, tenant_id, subject_user_id, reason, expires_at,
       requested_at, requested_by, request_command_id,
       approved_at, approved_by, approval_command_id,
       withdrawn_at, withdrawn_by
  FROM admin.authority_request;

GRANT SELECT ON api.authority_request TO app_admin_plane;

GRANT INSERT (scope, tenant_id, subject_user_id, reason, expires_at,
              requested_by, request_command_id)
  ON api.authority_request TO app_admin_plane;

GRANT UPDATE (approved_at, approved_by, approval_command_id,
              withdrawn_at, withdrawn_by)
  ON api.authority_request TO app_admin_plane;

CREATE OR REPLACE FUNCTION admin.request_is_signed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    PERFORM FROM admin.signed_command c
     WHERE c.id = NEW.request_command_id
       AND c.action = 'authority.request'
       AND c.scope = NEW.scope
       AND c.target_tenant_id IS NOT DISTINCT FROM NEW.tenant_id
       AND c.user_id = NEW.requested_by;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the request command is not this request, by %',
            NEW.requested_by
            USING ERRCODE = 'AD088',
                  HINT = 'A request is signed by whoever asks. Recycling '
                         'someone else''s command is what this refuses.';
    END IF;

    IF NEW.approved_at IS NOT NULL THEN
        PERFORM FROM admin.signed_command c
         WHERE c.id = NEW.approval_command_id
           AND c.action = 'authority.approve'
           AND c.scope = NEW.scope
           AND c.target_tenant_id IS NOT DISTINCT FROM NEW.tenant_id
           AND c.user_id = NEW.approved_by;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'the approval command is not this approval, by %',
                NEW.approved_by
                USING ERRCODE = 'AD088',
                      HINT = 'THE WHOLE POINT: the approval is signed by the '
                             'APPROVER, with their own hardware key. Otherwise '
                             'four eyes is a column somebody typed.';
        END IF;
        IF NOT admin.signs_here(NEW.approved_by, NEW.tenant_id) THEN
            RAISE EXCEPTION 'the approver holds no authority over that perimeter'
                USING ERRCODE = 'AD088';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

ALTER TABLE admin.authority_request
    DROP CONSTRAINT authority_request_withdrawal_is_signed;
ALTER TABLE admin.authority_request
    DROP CONSTRAINT authority_request_withdrawal_command_fk;
ALTER TABLE admin.authority_request
    DROP COLUMN withdrawal_command_id;

-- LE CODE RESTE AU VOCABULAIRE. Une commande déjà signée le référence, et
-- `command_action_no_delete` refuse de toute façon — c'est ce qui rend la
-- remontée idempotente.

RESET ROLE;
