-- Up Migration

-- « SE CONNECTER EN TANT QUE » — CE QUE TOUT SAAS B2B FAIT ET QU'AUCUN
-- SCHÉMA N'ÉCRIT.
--
-- Le support finit toujours par avoir besoin de voir ce que le client voit.
-- Tous les produits du marché le proposent ; la question n'est pas s'il faut
-- le faire, mais s'il en reste une trace. Un client entreprise fait inscrire
-- au contrat qu'aucun employé n'accède à son environnement sans consentement,
-- et il demande à le vérifier.
--
-- Ce schéma ne savait pas exprimer l'opération. Elle se serait donc faite
-- ailleurs — un jeton fabriqué à la main, une requête SQL, un contournement
-- sans trace. Le pire endroit où mettre l'accès le plus sensible du produit
-- est celui où il n'est pas modélisé.
--
--
-- ═══ 1. USURPER EXIGE UNE PRÉSENCE PHYSIQUE ═══
--
-- L'opération se rattache à une `signed_command`, donc à un défi WebAuthn
-- consommé. Un jeton d'administration volé ne suffit pas : il faut la clé
-- matérielle, au moment même.
--
-- C'est la contrainte la plus forte du schéma, et c'est ici qu'elle a le plus
-- de sens — parce que c'est la seule opération où un employé lit les données
-- d'un client sans que ce client soit dans la boucle.
--
--
-- ═══ 2. LE PLAFOND DÉPEND DE CELUI QUI DEMANDE ═══
--
-- Les produits du marché plafonnent par niveau : une vingtaine de minutes
-- pour un agent de support, une heure pour un ingénieur sur incident. Le
-- niveau existe déjà ici — c'est le PÉRIMÈTRE D'AUTORITÉ. Une colonne de plus
-- sur `authority_scope` suffit, et la politique reste au même endroit.
--
-- Le plafond est celui du périmètre le plus large que l'opérateur détient
-- VIVANT au moment de la demande. Une autorité expirée ne prête pas son
-- plafond.
--
--
-- ═══ 3. UNE SEULE À LA FOIS ═══
--
-- Un opérateur qui agit simultanément comme deux personnes ne fait pas du
-- support : il fait autre chose. L'unicité partielle le refuse, et elle rend
-- aussi la lecture du journal univoque — à un instant donné, une ligne dit
-- ce que cet opérateur était en train de voir.
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD090  the command spent is not an impersonation of this tenant
--     AD091  the operator holds no live authority over the target tenant
--     AD092  the session outruns the ceiling of the operator's widest scope
--     AD093  an impersonation is a fact: only its end may be written
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

-- Le plafond rejoint la politique, il ne part pas dans une table à lui : un
-- auditeur lit une ligne et sait tout ce qu'un périmètre autorise.
ALTER TABLE admin.authority_scope
    ADD COLUMN max_impersonation interval NOT NULL DEFAULT interval '20 minutes';

ALTER TABLE admin.authority_scope
    ADD CONSTRAINT authority_scope_impersonation_positive CHECK (
        max_impersonation > interval '0'),
    -- Personne ne peut usurper plus longtemps qu'il ne détient l'autorité de
    -- le faire. Sans cette ligne, une autorité de huit heures pourrait porter
    -- une session d'usurpation de douze.
    ADD CONSTRAINT authority_scope_impersonation_within_authority CHECK (
        max_impersonation <= max_duration);

UPDATE admin.authority_scope
   SET max_impersonation = interval '60 minutes' WHERE scope = 'PLATFORM';
UPDATE admin.authority_scope
   SET max_impersonation = interval '20 minutes' WHERE scope = 'TENANT';

COMMENT ON COLUMN admin.authority_scope.max_impersonation IS
'Combien de temps au plus un opérateur de ce périmètre peut agir à la place
d''un utilisateur. Une heure pour la plateforme — un ingénieur sur incident —
vingt minutes pour un périmètre de tenant. Les ordres de grandeur du marché,
et surtout : une durée, jamais « jusqu''à déconnexion ».';


CREATE TABLE admin.impersonation (
    id                uuid        NOT NULL DEFAULT gen_random_uuid(),

    -- LA PREUVE DE PRÉSENCE. Un jeton d'administration volé ne suffit pas :
    -- la commande signée a consommé un défi WebAuthn, donc la clé matérielle
    -- était là.
    command_id        uuid        NOT NULL,

    operator_user_id  uuid        NOT NULL,
    target_tenant_id  uuid        NOT NULL,
    -- L'utilisateur final dont on prend la place. Il vit dans auth, donc
    -- c'est une référence opaque : cette base doit tourner seule.
    subject_ref       uuid        NOT NULL,

    -- Le billet n'est pas décoratif. « Pourquoi as-tu ouvert le compte de ce
    -- client le 3 mars » est la question posée en revue, et un motif libre
    -- sans référence externe n'y répond pas.
    ticket_ref        text        NOT NULL,
    reason            text        NOT NULL,

    started_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL DEFAULT now() + interval '20 minutes',
    ended_at          timestamptz,
    end_reason        text,

    CONSTRAINT impersonation_pk PRIMARY KEY (id),
    CONSTRAINT impersonation_command_fk
        FOREIGN KEY (command_id) REFERENCES admin.signed_command (id)
        ON DELETE RESTRICT,
    -- Une présence, une usurpation. Réutiliser la même commande ouvrirait
    -- une seconde session sur une preuve déjà dépensée.
    CONSTRAINT uq_impersonation_command UNIQUE (command_id),
    CONSTRAINT impersonation_operator_fk
        FOREIGN KEY (operator_user_id) REFERENCES admin."user" (id),
    CONSTRAINT impersonation_expires_after_start CHECK (expires_at > started_at),
    CONSTRAINT impersonation_end_complete CHECK (
        (ended_at IS NULL AND end_reason IS NULL)
     OR (ended_at IS NOT NULL AND end_reason IS NOT NULL)),
    CONSTRAINT impersonation_ended_after_start CHECK (
        ended_at IS NULL OR ended_at >= started_at),
    CONSTRAINT impersonation_ticket_not_blank CHECK (btrim(ticket_ref) <> '')
);

-- Un opérateur agissant simultanément comme deux personnes ne fait pas du
-- support. Et l'unicité rend le journal univoque : à un instant donné, une
-- ligne dit ce que cet opérateur voyait.
CREATE UNIQUE INDEX uq_one_live_impersonation
    ON admin.impersonation (operator_user_id)
    WHERE ended_at IS NULL;

CREATE INDEX ix_impersonation_tenant
    ON admin.impersonation (target_tenant_id, started_at DESC);
CREATE INDEX ix_impersonation_subject
    ON admin.impersonation (subject_ref, started_at DESC);

COMMENT ON TABLE admin.impersonation IS
'Un employé agit à la place d''un utilisateur d''un client. L''opération la
plus sensible du produit : la seule où quelqu''un lit les données d''un client
sans que ce client soit dans la boucle.

Elle exige une commande signée, donc une clé matérielle présente au moment
même. Elle a un terme. Elle nomme un billet. Et elle ne s''efface pas.

L''index unique partiel sur un opérateur sans fin déclarée fait de « qui est
en train de regarder quoi » une question à réponse unique.';

COMMENT ON COLUMN admin.impersonation.subject_ref IS
'Référence opaque vers l''utilisateur de auth. Pas de clé étrangère : chaque
base doit pouvoir tourner sur un serveur seul, et check-orphans réconcilie
ce qui doit l''être.';


CREATE FUNCTION admin.impersonation_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    cap interval;
BEGIN
    -- La commande dépensée doit être CELLE-CI : même opérateur, même tenant,
    -- action d'usurpation. Sans ces trois égalités, une présence prouvée pour
    -- « exporter un rapport » ouvrirait une session dans le compte d'un
    -- client — c'est le même raisonnement que AD080, appliqué au cas où il
    -- coûte le plus cher.
    PERFORM FROM admin.signed_command c
     WHERE c.id = NEW.command_id
       AND c.action = 'impersonate'
       AND c.scope = 'TENANT'
       AND c.target_tenant_id = NEW.target_tenant_id
       AND c.user_id = NEW.operator_user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'the signed command spent is not an impersonation of tenant % by %',
            NEW.target_tenant_id, NEW.operator_user_id
            USING ERRCODE = 'AD090';
    END IF;

    IF NOT admin.may_operate(NEW.operator_user_id, NEW.target_tenant_id) THEN
        RAISE EXCEPTION 'operator % holds no live authority over tenant %',
            NEW.operator_user_id, NEW.target_tenant_id
            USING ERRCODE = 'AD091';
    END IF;

    -- Le plafond du périmètre le plus large détenu VIVANT. Une autorité
    -- expirée ne prête pas son plafond : c'est la même autorité qui donne le
    -- droit d'agir et la durée pendant laquelle on peut le faire.
    SELECT max(s.max_impersonation) INTO cap
      FROM admin.effective_authority e
      JOIN admin.authority_scope s ON s.scope = e.scope
     WHERE e.user_id = NEW.operator_user_id
       AND (e.scope = 'PLATFORM' OR e.tenant_id = NEW.target_tenant_id);

    -- Fermé par défaut : sans plafond trouvé, on refuse. may_operate vient de
    -- dire oui, donc une absence ici signale une politique incomplète, pas
    -- une permission.
    IF cap IS NULL OR NEW.expires_at - NEW.started_at > cap THEN
        RAISE EXCEPTION
            'impersonation may not run longer than %, asked for %',
            coalesce(cap::text, '(no ceiling declared)'),
            NEW.expires_at - NEW.started_at
            USING ERRCODE = 'AD092';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER impersonation_guard
    BEFORE INSERT ON admin.impersonation
    FOR EACH ROW EXECUTE FUNCTION admin.impersonation_guard();


CREATE FUNCTION admin.impersonation_end_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.ended_at IS NOT NULL THEN
        RAISE EXCEPTION 'this impersonation has already ended'
            USING ERRCODE = 'AD093';
    END IF;
    IF NEW.command_id       IS DISTINCT FROM OLD.command_id
    OR NEW.operator_user_id IS DISTINCT FROM OLD.operator_user_id
    OR NEW.target_tenant_id IS DISTINCT FROM OLD.target_tenant_id
    OR NEW.subject_ref      IS DISTINCT FROM OLD.subject_ref
    OR NEW.ticket_ref       IS DISTINCT FROM OLD.ticket_ref
    OR NEW.reason           IS DISTINCT FROM OLD.reason
    OR NEW.started_at       IS DISTINCT FROM OLD.started_at
    -- expires_at compris : rallonger une session en cours, c'est le plafond
    -- qui ne veut plus rien dire.
    OR NEW.expires_at       IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'an impersonation is a fact: only its end may be written'
            USING ERRCODE = 'AD093';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER impersonation_end_only
    BEFORE UPDATE ON admin.impersonation
    FOR EACH ROW EXECUTE FUNCTION admin.impersonation_end_only();

CREATE TRIGGER impersonation_no_delete
    BEFORE DELETE ON admin.impersonation
    FOR EACH ROW EXECUTE FUNCTION admin.authority_no_delete();


CREATE VIEW admin.impersonation_live
    WITH (security_invoker = TRUE)
AS
SELECT i.id, i.operator_user_id, i.target_tenant_id, i.subject_ref,
       i.ticket_ref, i.reason, i.started_at, i.expires_at,
       i.expires_at - now() AS time_left
  FROM admin.impersonation AS i
 WHERE i.ended_at IS NULL
   AND now() < i.expires_at;

COMMENT ON VIEW admin.impersonation_live IS
'Qui regarde quoi, maintenant. Une session dont le terme est passé n''y
figure plus même si personne n''a écrit sa fin : l''expiration est dérivée,
donc elle ne dépend pas d''un client qui se déconnecte proprement.';


GRANT SELECT, INSERT, UPDATE ON admin.impersonation TO admin_app;
GRANT SELECT ON admin.impersonation_live TO admin_app;

REVOKE EXECUTE ON FUNCTION admin.impersonation_guard()    FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION admin.impersonation_end_only() FROM PUBLIC;

RESET ROLE;

SELECT audit.watch('admin', 'impersonation',
       '{id, command_id, operator_user_id, target_tenant_id, subject_ref,
         ticket_ref, reason, started_at, expires_at, ended_at, end_reason}');
SELECT audit.watch('admin', 'authority_scope',
       '{scope, max_duration, max_impersonation, requires_second_approver,
         allows_break_glass}');

-- Down Migration

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name = 'impersonation';
DELETE FROM audit.watched
 WHERE schema_name = 'admin' AND table_name = 'impersonation';
SELECT audit.watch('admin', 'authority_scope',
       '{scope, max_duration, requires_second_approver, allows_break_glass}');

DROP VIEW admin.impersonation_live;
DROP TRIGGER impersonation_no_delete ON admin.impersonation;
DROP TRIGGER impersonation_end_only ON admin.impersonation;
DROP TRIGGER impersonation_guard ON admin.impersonation;
DROP FUNCTION admin.impersonation_end_only();
DROP FUNCTION admin.impersonation_guard();
DROP TABLE admin.impersonation;

ALTER TABLE admin.authority_scope
    DROP CONSTRAINT authority_scope_impersonation_within_authority,
    DROP CONSTRAINT authority_scope_impersonation_positive,
    DROP COLUMN max_impersonation;
