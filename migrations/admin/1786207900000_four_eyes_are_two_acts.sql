-- Up Migration

-- LA RÈGLE DES QUATRE YEUX ÉTAIT UNE COLONNE, PAS UN ACTE.
--
-- `AD075` exige un second approbateur DISTINCT sur le périmètre plateforme, et
-- c'est bien la protection du plus haut privilège du produit. Sauf que
-- `approved_by` est écrit par LE MÊME APPELANT, dans LA MÊME transaction, que
-- `granted_by`.
--
-- Le second approbateur ne signe rien. Il ne consomme aucun défi. Il n'a même
-- pas besoin d'une session ouverte. `AD075` prouve donc qu'UN SECOND UUID A ÉTÉ
-- SAISI, pas qu'un second humain a approuvé. C'est la protection la plus faible
-- de cette base, et elle garde ce qu'il y a de plus lourd.
--
-- Un vrai second regard, c'est deux ACTES : quelqu'un demande, quelqu'un
-- d'autre approuve, chacun avec sa propre clé matérielle et sa propre commande
-- signée. Deux lignes dans le temps, pas deux colonnes dans une ligne.
--
--
-- ═══ SEULEMENT LÀ OÙ LA RÈGLE EXISTE ═══
--
-- `authority_scope.requires_second_approver` dit déjà où les quatre yeux
-- s'appliquent : sur `PLATFORM`, pas sur `TENANT`. Le parcours de demande suit
-- cette colonne plutôt qu'une seconde liste — l'administrateur d'un client
-- continue d'accorder à son collègue en un geste, ce qui est proportionné,
-- et personne n'a à tenir deux règles cohérentes à la main.
--
-- Conséquence : `admin_tenant` n'est pas touchée. Le quotidien d'un client ne
-- passe pas par une file d'attente.
--
--
-- ═══ CE QUE LE BRIS DE GLACE DEVIENT ═══
--
-- Il ne change pas : il contourne le second approbateur, donc il contourne la
-- demande. C'était déjà son sens — « une seule signature, assumée, et le
-- drapeau la rend relisible ». Un octroi de bris de glace n'a donc pas de
-- demande, et `break_glass_use` reste la liste qu'on relit après coup.
--
--
-- ═══ TROIS PERSONNES, ET AUCUNE N'EST LA MÊME ═══
--
-- Le demandeur, l'approbateur et le bénéficiaire sont distincts deux à deux.
-- Demander pour soi puis se faire approuver est déjà couvert par AD074 côté
-- octroi ; l'interdire ICI le refuse une étape plus tôt, avant qu'une clé
-- matérielle soit dérangée.
--
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD086  this scope needs an APPROVED request, and it has none
--     AD087  the request does not describe this grant
--     AD088  a request and its approval are each signed by their own author
--     AD089  a request is a fact: only its approval or its withdrawal is written
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- ON CONFLICT : la descente ne retire pas un code encore référencé (voir plus
-- bas), donc la remontée peut le retrouver en place.
INSERT INTO admin.command_action (code, description, applies_to) VALUES
  ('authority.request', 'Demander une autorité pour quelqu''un d''autre.', 'ANY'),
  ('authority.approve', 'Approuver la demande d''un autre — le second regard.', 'ANY')
ON CONFLICT (code) DO NOTHING;


CREATE TABLE admin.authority_request (
    id              uuid        NOT NULL DEFAULT gen_random_uuid(),

    scope           text        NOT NULL,
    tenant_id       uuid,
    -- POUR QUI. Jamais pour soi : voir l'entête.
    subject_user_id uuid        NOT NULL,
    reason          text        NOT NULL,
    -- Le terme demandé, facultatif comme partout depuis
    -- `authority_does_not_lapse`.
    expires_at      timestamptz,

    requested_at    timestamptz NOT NULL DEFAULT now(),
    requested_by    uuid        NOT NULL,
    request_command_id uuid     NOT NULL,

    -- LE SECOND ACTE. Il arrive plus tard, signé par quelqu'un d'autre.
    approved_at     timestamptz,
    approved_by     uuid,
    approval_command_id uuid,

    -- Une demande qu'on retire vaut mieux qu'une demande qui traîne : sans
    -- ça, la file d'attente devient l'endroit où les décisions vont mourir.
    withdrawn_at    timestamptz,
    withdrawn_by    uuid,

    CONSTRAINT authority_request_pk PRIMARY KEY (id),

    CONSTRAINT authority_request_scope_fk
        FOREIGN KEY (scope) REFERENCES admin.authority_scope (scope)
        ON DELETE RESTRICT,
    CONSTRAINT authority_request_subject_fk
        FOREIGN KEY (subject_user_id) REFERENCES admin."user" (id)
        ON DELETE RESTRICT,
    CONSTRAINT authority_request_requested_by_fk
        FOREIGN KEY (requested_by) REFERENCES admin."user" (id)
        ON DELETE RESTRICT,
    CONSTRAINT authority_request_approved_by_fk
        FOREIGN KEY (approved_by) REFERENCES admin."user" (id)
        ON DELETE RESTRICT,
    CONSTRAINT authority_request_withdrawn_by_fk
        FOREIGN KEY (withdrawn_by) REFERENCES admin."user" (id)
        ON DELETE RESTRICT,
    CONSTRAINT authority_request_command_fk
        FOREIGN KEY (request_command_id) REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT,
    CONSTRAINT authority_request_approval_command_fk
        FOREIGN KEY (approval_command_id) REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT,

    -- La même cohérence portée/cible que partout ailleurs.
    CONSTRAINT authority_request_target_matches_scope CHECK (
        (scope = 'TENANT'   AND tenant_id IS NOT NULL) OR
        (scope = 'PLATFORM' AND tenant_id IS NULL)),

    -- L'approbation est un fait complet ou absente : la date, l'auteur et la
    -- commande vont ensemble.
    CONSTRAINT authority_request_approval_complete CHECK (
        (approved_at IS NULL) = (approved_by IS NULL)
    AND (approved_at IS NULL) = (approval_command_id IS NULL)),
    CONSTRAINT authority_request_withdrawal_complete CHECK (
        (withdrawn_at IS NULL) = (withdrawn_by IS NULL)),
    -- Approuvée ET retirée ne décrit rien.
    CONSTRAINT authority_request_one_outcome CHECK (
        approved_at IS NULL OR withdrawn_at IS NULL),

    -- TROIS PERSONNES DISTINCTES. C'est la raison d'être de la table.
    CONSTRAINT authority_request_not_for_oneself CHECK (
        requested_by <> subject_user_id),
    CONSTRAINT authority_request_approver_is_a_third CHECK (
        approved_by IS NULL
        OR (approved_by <> requested_by AND approved_by <> subject_user_id))
);

CREATE INDEX ix_authority_request_open ON admin.authority_request (scope)
    WHERE approved_at IS NULL AND withdrawn_at IS NULL;
CREATE INDEX ix_authority_request_subject
    ON admin.authority_request (subject_user_id);

COMMENT ON TABLE admin.authority_request IS
'Les quatre yeux, en deux actes. `approved_by` était une colonne écrite par le
même appelant dans la même transaction que `granted_by` : elle prouvait qu''un
second uuid avait été saisi, pas qu''un second humain avait approuvé. Ici la
demande et l''approbation sont deux écritures, deux clés matérielles, deux
commandes signées.';

COMMENT ON COLUMN admin.authority_request.subject_user_id IS
'Le bénéficiaire, et jamais le demandeur. Demander pour soi est refusé ici,
une étape avant AD074 — donc avant qu''une clé matérielle soit dérangée.';

COMMENT ON COLUMN admin.authority_request.withdrawn_at IS
'Retirer vaut mieux que laisser traîner : une file d''attente sans sortie
devient l''endroit où les décisions vont mourir, et où l''on finit par
contourner la règle plutôt que l''appliquer.';


CREATE VIEW admin.pending_request
    WITH (security_invoker = TRUE)
AS
SELECT r.id, r.scope, r.tenant_id, r.subject_user_id, r.reason, r.expires_at,
       r.requested_at, r.requested_by, now() - r.requested_at AS waiting
  FROM admin.authority_request AS r
 WHERE r.approved_at IS NULL AND r.withdrawn_at IS NULL;

COMMENT ON VIEW admin.pending_request IS
'Ce qui attend un second regard, et depuis combien de temps. `waiting` est
calculé : une demande qui dort trois semaines se voit sans qu''aucune tâche
planifiée ait à la signaler.';

CREATE VIEW api.authority_request AS
  SELECT id, scope, tenant_id, subject_user_id, reason, expires_at,
         requested_at, requested_by, approved_at, approved_by,
         withdrawn_at, withdrawn_by
    FROM admin.authority_request;

CREATE VIEW api.pending_request
    WITH (security_invoker = TRUE)
AS
  SELECT id, scope, tenant_id, subject_user_id, reason, expires_at, requested_at,
         requested_by, waiting
    FROM admin.pending_request;

GRANT SELECT, INSERT ON api.authority_request TO app_admin_plane;
GRANT SELECT ON api.pending_request TO app_admin_plane;
GRANT SELECT, INSERT ON admin.authority_request TO app_admin_plane;
GRANT UPDATE (approved_at, approved_by, approval_command_id,
              withdrawn_at, withdrawn_by)
    ON admin.authority_request TO app_admin_plane;


-- =====================================================================
--  CHAQUE ACTE PORTE SA SIGNATURE
-- =====================================================================

CREATE FUNCTION admin.request_is_signed()
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

    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.request_is_signed() FROM PUBLIC;


CREATE FUNCTION admin.request_is_a_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.approved_at IS NOT NULL OR OLD.withdrawn_at IS NOT NULL THEN
        RAISE EXCEPTION 'this request is already settled'
            USING ERRCODE = 'AD089';
    END IF;
    IF NEW.scope           IS DISTINCT FROM OLD.scope
    OR NEW.tenant_id       IS DISTINCT FROM OLD.tenant_id
    OR NEW.subject_user_id IS DISTINCT FROM OLD.subject_user_id
    OR NEW.reason          IS DISTINCT FROM OLD.reason
    OR NEW.expires_at      IS DISTINCT FROM OLD.expires_at
    OR NEW.requested_by    IS DISTINCT FROM OLD.requested_by
    OR NEW.requested_at    IS DISTINCT FROM OLD.requested_at
    OR NEW.request_command_id IS DISTINCT FROM OLD.request_command_id THEN
        RAISE EXCEPTION 'a request is a fact: only its outcome may be written'
            USING ERRCODE = 'AD089',
                  HINT = 'Approving something other than what was asked is how '
                         'a second pair of eyes stops meaning anything.';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.request_is_a_fact() FROM PUBLIC;

CREATE TRIGGER authority_request_is_signed
    BEFORE INSERT OR UPDATE ON admin.authority_request
    FOR EACH ROW EXECUTE FUNCTION admin.request_is_signed();

CREATE TRIGGER authority_request_is_a_fact
    BEFORE UPDATE ON admin.authority_request
    FOR EACH ROW EXECUTE FUNCTION admin.request_is_a_fact();

CREATE TRIGGER authority_request_no_delete
    BEFORE DELETE ON admin.authority_request
    FOR EACH ROW EXECUTE FUNCTION admin.no_delete();


-- =====================================================================
--  L'OCTROI CITE LA DEMANDE QUI L'A AUTORISÉ
-- =====================================================================

ALTER TABLE admin.platform_admin
    ADD COLUMN request_id uuid REFERENCES admin.authority_request (id)
        ON DELETE RESTRICT;

COMMENT ON COLUMN admin.platform_admin.request_id IS
'La demande approuvée dont cet octroi découle. NULL sur la genèse, sur
l''historique antérieur à cette règle, et sur un bris de glace — qui contourne
justement le second approbateur, et le dit.';

CREATE FUNCTION admin.grant_follows_a_request()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    pol record;
    req record;
BEGIN
    SELECT * INTO pol FROM admin.authority_scope WHERE scope = TG_ARGV[0];
    IF NOT FOUND OR NOT pol.requires_second_approver THEN
        RETURN NEW;
    END IF;

    -- Le bris de glace contourne le second approbateur : c'est sa définition,
    -- et `break_glass_use` le rend relisible après coup.
    IF NEW.break_glass THEN
        RETURN NEW;
    END IF;

    -- LA GENÈSE, comme partout : la première autorité de plateforme précède
    -- toute demande, puisqu'il n'y a encore personne pour approuver.
    IF NOT EXISTS (SELECT FROM admin.platform_admin) THEN
        RETURN NEW;
    END IF;

    IF NEW.request_id IS NULL THEN
        RAISE EXCEPTION 'the % scope needs an approved request', pol.scope
            USING ERRCODE = 'AD086',
                  HINT = 'Two acts: someone asks, someone else approves, each '
                         'with their own hardware key. A second uuid in a '
                         'column is not a second pair of eyes.';
    END IF;

    SELECT * INTO req FROM admin.authority_request WHERE id = NEW.request_id;

    IF req.approved_at IS NULL OR req.withdrawn_at IS NOT NULL THEN
        RAISE EXCEPTION 'request % is not approved', NEW.request_id
            USING ERRCODE = 'AD086';
    END IF;

    -- `expires_at` EN FAIT PARTIE : approuver « trois jours » et accorder dix
    -- ans laisserait le second regard porter sur autre chose que l'octroi.
    IF req.scope <> TG_ARGV[0]
    OR req.subject_user_id <> NEW.user_id
    OR req.requested_by    <> NEW.granted_by
    OR req.approved_by     IS DISTINCT FROM NEW.approved_by
    OR req.expires_at      IS DISTINCT FROM NEW.expires_at THEN
        RAISE EXCEPTION
            'the request approved does not describe this grant'
            USING ERRCODE = 'AD087',
                  HINT = 'NEVER RETRY, AND ALERT. The row granted is not what '
                         'the second pair of eyes looked at.';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.grant_follows_a_request() FROM PUBLIC;

COMMENT ON FUNCTION admin.grant_follows_a_request IS
'Ce qui rend AD075 vrai. Il exigeait un second uuid distinct ; ici l''octroi
doit citer une demande APPROUVÉE, dont le demandeur et l''approbateur sont ceux
que la ligne nomme — chacun ayant signé son propre acte.';

-- `zzz_` : après toutes les autres gardes de l'octroi. Se faire refuser pour
-- une durée illégale ou un auto-octroi avant qu'on aille lire la demande donne
-- le message le plus utile.
CREATE TRIGGER zzz_platform_admin_follows_a_request
    BEFORE INSERT ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.grant_follows_a_request('PLATFORM');


SELECT audit.watch('admin', 'authority_request',
       '{id, scope, tenant_id, subject_user_id, reason, expires_at,
         requested_at, requested_by, request_command_id,
         approved_at, approved_by, approval_command_id,
         withdrawn_at, withdrawn_by}');

INSERT INTO audit.auditable_column (schema_name, table_name, column_name)
VALUES ('admin', 'platform_admin', 'request_id');

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name = 'platform_admin'
   AND column_name = 'request_id';

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name = 'authority_request';
DELETE FROM audit.watched
 WHERE schema_name = 'admin' AND table_name = 'authority_request';

DROP TRIGGER zzz_platform_admin_follows_a_request ON admin.platform_admin;
DROP FUNCTION admin.grant_follows_a_request();

ALTER TABLE admin.platform_admin DROP COLUMN request_id;

DROP TRIGGER authority_request_no_delete ON admin.authority_request;
DROP TRIGGER authority_request_is_a_fact ON admin.authority_request;
DROP TRIGGER authority_request_is_signed ON admin.authority_request;
DROP FUNCTION admin.request_is_a_fact();
DROP FUNCTION admin.request_is_signed();

DROP VIEW api.pending_request;
DROP VIEW api.authority_request;
DROP VIEW admin.pending_request;
DROP TABLE admin.authority_request;

-- UN CODE ENCORE RÉFÉRENCÉ NE SE RETIRE PAS. Des défis et des commandes déjà
-- écrits le portent : le supprimer orphelinerait ce qu'un administrateur a
-- fait, ce que la clé étrangère refuse et ce qu'on ne veut pas de toute façon.
ALTER TABLE admin.command_action DISABLE TRIGGER command_action_no_delete;
DELETE FROM admin.command_action c
 WHERE c.code IN ('authority.request', 'authority.approve')
   AND NOT EXISTS (SELECT FROM webauthn.challenge AS x WHERE x.action = c.code)
   AND NOT EXISTS (SELECT FROM admin.signed_command AS x WHERE x.action = c.code);
ALTER TABLE admin.command_action ENABLE TRIGGER command_action_no_delete;

RESET ROLE;
