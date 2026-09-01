-- Up Migration

-- UN RETRAIT SANS AUTEUR EST INCOMPLET, PAS NON SIGNÉ.
--
-- ═══ UN DÉCLENCHEUR A VOLÉ LA PAROLE À UNE CONTRAINTE ═══
--
-- `a_withdrawal_is_signed_like_the_rest` a étendu `request_is_signed` pour
-- exiger que le retrait cite une commande `authority.withdraw` de celui qui est
-- nommé comme retirant. Le bloc se déclenche sur `NEW.withdrawn_at IS NOT NULL`,
-- et rien d'autre.
--
-- Conséquence, mesurée par un banc qui existait déjà :
--
--     UPDATE admin.authority_request SET withdrawn_at = now() WHERE id = …
--     -- attendu : 23514 authority_request_withdrawal_complete
--     -- obtenu  : AD088 « the withdrawal command is not this withdrawal, by <NULL> »
--
-- `TestAnApprovalIsATripletOrNothing` l'a dit dans ces mots : « refusé par
-- AD088, sans contrainte nommée — un déclencheur a parlé avant ». Un retrait
-- sans auteur n'est pas un retrait mal signé : c'est un retrait à moitié écrit,
-- et `authority_request_withdrawal_complete` le dit mieux — la date et l'auteur
-- vont ensemble.
--
-- Le refus restait juste ; c'est sa DESCRIPTION qui devenait fausse. Et un
-- message qui décrit mal ce qu'on a fait de travers est ce qui fait chercher au
-- mauvais endroit — ici, une commande manquante au lieu d'une colonne oubliée.
--
-- ═══ LA MAISON AVAIT DÉJÀ TRANCHÉ, UNE TABLE PLUS LOIN ═══
--
-- `authority_is_signed` porte exactement cette garde, avec sa raison écrite :
--
--     -- Sans auteur, `revocation_complete` dit mieux la même chose : la
--     -- date et l'auteur vont ensemble. On lui laisse la parole.
--     IF NEW.revoked_by IS NULL THEN
--         RETURN NEW;
--     END IF;
--
-- La migration précédente ne l'a pas recopiée. Celle-ci le fait, et c'est tout
-- ce qu'elle fait : un `AND NEW.withdrawn_by IS NOT NULL` sur la condition
-- d'entrée du troisième bloc.
--
-- ═══ CE QUE ÇA N'AFFAIBLIT PAS ═══
--
-- Rien. Un retrait dont l'auteur est nul ne passe pas davantage — il est refusé
-- par `authority_request_withdrawal_complete` (23514), donc par une contrainte
-- NOMMÉE, qu'un test peut désigner. Un retrait avec auteur reste soumis à AD088
-- comme avant. Les deux gardes couvrent les mêmes cas ; elles se répartissent
-- seulement la parole selon ce qui décrit le mieux la faute.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   Aucun code nouveau. Elle rend `23514`
--   `authority_request_withdrawal_complete` de nouveau atteignable, là où AD088
--   le masquait.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

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

    -- LE RETRAIT, MÊME EXIGENCE QUE LES DEUX AUTRES — et la même réserve que
    -- dans `authority_is_signed` : sans auteur, `withdrawal_complete` dit mieux
    -- la même chose, la date et l'auteur vont ensemble. On lui laisse la parole.
    --
    -- On ne vérifie PAS que l'auteur est le demandeur : voir
    -- `a_withdrawal_is_signed_like_the_rest`, la règle n'est pas tranchée.
    IF NEW.withdrawn_at IS NOT NULL AND NEW.withdrawn_by IS NOT NULL THEN
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

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

-- On repose la version qui parlait trop tôt. Elle refuse les mêmes écritures ;
-- elle les décrit seulement plus mal.

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

RESET ROLE;
