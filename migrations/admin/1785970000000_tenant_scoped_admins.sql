-- Up Migration

-- DES ADMINS PAR TENANT, ET DES ADMINS GLOBAUX.
--
-- L'AXIOME D'ABORD, parce que tout le reste en découle :
--
--   L'AUTORITÉ D'UN ADMIN NE DÉRIVE PAS D'IAM. ELLE LA PRÉCÈDE.
--
-- Un admin a par construction pouvoir sur la gestion des droits. Soumettre
-- ses actions à un contrôle IAM serait circulaire : IAM déciderait qui a le
-- droit de modifier IAM. Deux conséquences, toutes deux fatales.
--
--   Un DENY mal posé, ou un miroir d'adhésions en retard, et plus personne
--   ne peut réparer IAM — la seule voie de réparation étant elle-même sous
--   contrôle d'IAM. La plateforme se condamne toute seule.
--
--   Et dans l'autre sens : si un droit IAM suffisait à administrer, alors
--   un octroi IAM deviendrait un chemin d'élévation vers l'admin. Les deux
--   rayons d'explosion fusionneraient, ce qui est exactement ce que leur
--   séparation devait empêcher.
--
-- Un admin qui passerait par IAM redeviendrait un utilisateur lambda.
--
-- COROLLAIRE, et c'est LA décision de conception de cette migration :
--
--   LA PORTÉE EST LE SEUL LEVIER SUR UN ADMIN.
--
-- On ne restreint pas CE QU'un admin peut faire — cela reviendrait à poser
-- des droits sur les droits, donc à réintroduire la circularité par la
-- fenêtre. On restreint SUR QUOI il peut le faire. À l'intérieur de sa
-- portée, son autorité est entière ; en dehors, elle est nulle. Il n'y a
-- pas de granularité intermédiaire, et il ne faut pas en ajouter : le jour
-- où cette base gagne une table `admin.permission`, elle est devenue un
-- second IAM et l'axiome ci-dessus est mort.
--
-- L'autorité vient d'ici et de nulle part ailleurs : une session vivante,
-- une présence matérielle, une commande signée par la clé de l'admin — et
-- désormais une portée. La séparation est déjà structurelle : `admin` et
-- `iam` sont deux BASES distinctes, et `check-autonomy` prouve que chacune
-- se lève seule. IAM ne PEUT pas contrôler admin, même par erreur.
--
--
-- POURQUOI DEUX TABLES ET PAS UN tenant_id NULLABLE
--
-- `tenant_id NULL = global` est le réflexe, et il inverse le fail-closed de
-- ces quatre bases :
--
--   · `WHERE tenant_id = current_setting(...)` exclut silencieusement les
--     NULL, donc les admins globaux perdent leurs droits — en production.
--   · Le correctif universel, `OR tenant_id IS NULL`, est à une parenthèse
--     près de tout donner à tout le monde.
--   · Un index unique traite les NULL comme distincts : deux lignes
--     « globale » pour la même personne passent sans bruit.
--   · Et surtout : UN tenant_id OUBLIÉ À L'INSERT CRÉE UN ADMIN GLOBAL.
--     L'omission fabriquerait le plus haut privilège. C'est l'inverse exact
--     de la liste blanche d'audit, où l'oubli expurge.
--
-- Ici, être global est UNE LIGNE QUE QUELQU'UN A CRÉÉE, datée, motivée,
-- révocable. L'absence de ligne est le moindre privilège.
--
--
-- LE TENANT EST OPAQUE, ET C'EST VOULU
--
-- Aucune clé étrangère vers un tenant : cette base ne connaît pas ceux
-- d'auth, et ne doit pas en dépendre pour se lever. Conséquence heureuse
-- ici, contrairement à crypto : une portée accordée sur un tenant qui
-- n'existe pas ne donne accès à RIEN. La faute de frappe échoue fermée.
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD070  authority may not be granted to a deactivated admin
--     AD071  authority is never deleted; post a revocation instead
--     AD072  only the revocation may be written, and only once
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

-- =====================================================================
--  1. PORTÉE PAR TENANT
-- =====================================================================

CREATE TABLE admin.admin_tenant (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL,
    tenant_id   uuid        NOT NULL,

    granted_at  timestamptz NOT NULL DEFAULT now(),
    granted_by  uuid        NOT NULL,
    reason      text        NOT NULL,

    revoked_at  timestamptz,
    revoked_by  uuid,

    CONSTRAINT admin_tenant_pk PRIMARY KEY (id),
    CONSTRAINT admin_tenant_user_fk
        FOREIGN KEY (user_id)    REFERENCES admin."user" (id),
    CONSTRAINT admin_tenant_granted_by_fk
        FOREIGN KEY (granted_by) REFERENCES admin."user" (id),
    CONSTRAINT admin_tenant_revoked_by_fk
        FOREIGN KEY (revoked_by) REFERENCES admin."user" (id),
    CONSTRAINT admin_tenant_revocation_complete CHECK (
        (revoked_at IS NULL     AND revoked_by IS NULL)
     OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL)),
    CONSTRAINT admin_tenant_revoked_after_granted CHECK (
        revoked_at IS NULL OR revoked_at >= granted_at)
);

-- Une seule portée VIVANTE par (admin, tenant). Les révoquées s'empilent :
-- l'historique de qui a pu opérer sur quoi, et quand, est la moitié de
-- l'intérêt de cette table.
CREATE UNIQUE INDEX admin_tenant_one_live
    ON admin.admin_tenant (user_id, tenant_id) WHERE revoked_at IS NULL;

CREATE INDEX admin_tenant_by_tenant
    ON admin.admin_tenant (tenant_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE admin.admin_tenant IS
'Sur quels tenants un admin peut opérer. Une ligne par tenant : un admin
sur trois tenants, ce sont trois lignes — ce qu''un tenant_id unique ne sait
pas exprimer.

À l''intérieur de cette portée son autorité est ENTIÈRE. Il n''existe pas de
permission plus fine, par conception : voir l''entête de cette migration.';

COMMENT ON COLUMN admin.admin_tenant.tenant_id IS
'Opaque. Cette base ne connaît pas les tenants d''auth et n''a pas de clé
étrangère vers eux — elle doit pouvoir se lever seule. Une portée sur un
tenant inexistant ne donne accès à rien : la faute de frappe échoue fermée.';


-- =====================================================================
--  2. PORTÉE GLOBALE
-- =====================================================================

CREATE TABLE admin.platform_admin (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL,

    granted_at  timestamptz NOT NULL DEFAULT now(),
    granted_by  uuid        NOT NULL,
    reason      text        NOT NULL,

    revoked_at  timestamptz,
    revoked_by  uuid,

    CONSTRAINT platform_admin_pk PRIMARY KEY (id),
    CONSTRAINT platform_admin_user_fk
        FOREIGN KEY (user_id)    REFERENCES admin."user" (id),
    CONSTRAINT platform_admin_granted_by_fk
        FOREIGN KEY (granted_by) REFERENCES admin."user" (id),
    CONSTRAINT platform_admin_revoked_by_fk
        FOREIGN KEY (revoked_by) REFERENCES admin."user" (id),
    CONSTRAINT platform_admin_revocation_complete CHECK (
        (revoked_at IS NULL     AND revoked_by IS NULL)
     OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL)),
    CONSTRAINT platform_admin_revoked_after_granted CHECK (
        revoked_at IS NULL OR revoked_at >= granted_at)
);

CREATE UNIQUE INDEX platform_admin_one_live
    ON admin.platform_admin (user_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE admin.platform_admin IS
'Autorité sur TOUS les tenants. Une table séparée plutôt qu''un tenant_id
NULL : être global est une ligne que quelqu''un a créée, avec un motif et une
date, pas une colonne que quelqu''un a oubliée de remplir.

reason n''est pas décoratif — c''est le plus haut privilège de la plateforme,
et un octroi sans justification lisible ne s''audite pas.';


-- =====================================================================
--  3. GARDES
-- =====================================================================

-- Pas d'autorité DORMANTE : accorder une portée à un admin désactivé
-- créerait un droit qui s'activerait tout seul à sa réactivation. Même
-- raisonnement qu'IA001 dans iam.
CREATE FUNCTION admin.authority_grant_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    IF EXISTS (SELECT FROM admin."user" u
                WHERE u.id = NEW.user_id AND u.deactivated_at IS NOT NULL) THEN
        RAISE EXCEPTION 'admin % is deactivated: authority would lie dormant',
            NEW.user_id
            USING ERRCODE = 'AD070';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER admin_tenant_grant_guard
    BEFORE INSERT ON admin.admin_tenant
    FOR EACH ROW EXECUTE FUNCTION admin.authority_grant_guard();

CREATE TRIGGER platform_admin_grant_guard
    BEFORE INSERT ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.authority_grant_guard();


-- L'autorité ne se supprime pas : elle se révoque. Une ligne effacée, c'est
-- une question à laquelle on ne peut plus répondre — « qui pouvait opérer
-- sur ce tenant le 3 mars ? ».
CREATE FUNCTION admin.authority_no_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'authority is never deleted: post revoked_at instead'
        USING ERRCODE = 'AD071';
END;
$$;

CREATE TRIGGER admin_tenant_no_delete
    BEFORE DELETE ON admin.admin_tenant
    FOR EACH ROW EXECUTE FUNCTION admin.authority_no_delete();

CREATE TRIGGER platform_admin_no_delete
    BEFORE DELETE ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.authority_no_delete();


-- Seule la révocation s'écrit, et une seule fois. Sans ça, « révoqué » se
-- réécrit en « jamais révoqué » et l'historique ment.
CREATE FUNCTION admin.authority_revocation_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'authority % is already revoked', OLD.id
            USING ERRCODE = 'AD072';
    END IF;

    IF NEW.id         IS DISTINCT FROM OLD.id
    OR NEW.user_id    IS DISTINCT FROM OLD.user_id
    OR NEW.granted_at IS DISTINCT FROM OLD.granted_at
    OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
    OR NEW.reason     IS DISTINCT FROM OLD.reason THEN
        RAISE EXCEPTION 'only the revocation may be written'
            USING ERRCODE = 'AD072';
    END IF;

    IF NEW.revoked_at IS NULL THEN
        RAISE EXCEPTION 'this UPDATE carries no revocation'
            USING ERRCODE = 'AD072';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER admin_tenant_revocation_only
    BEFORE UPDATE ON admin.admin_tenant
    FOR EACH ROW EXECUTE FUNCTION admin.authority_revocation_only();

CREATE TRIGGER platform_admin_revocation_only
    BEFORE UPDATE ON admin.platform_admin
    FOR EACH ROW EXECUTE FUNCTION admin.authority_revocation_only();


-- =====================================================================
--  4. LIRE L'AUTORITÉ
-- =====================================================================

-- Le cas global est NOMMÉ, jamais impliqué. C'est plus long à lire qu'un
-- `OR tenant_id IS NULL`, et c'est le but : on voit l'élévation.
CREATE FUNCTION admin.may_operate(p_user uuid, p_tenant uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT FROM admin.platform_admin p
     WHERE p.user_id = p_user AND p.revoked_at IS NULL)
  OR EXISTS (
    SELECT FROM admin.admin_tenant t
     WHERE t.user_id = p_user AND t.tenant_id = p_tenant
       AND t.revoked_at IS NULL);
$$;

COMMENT ON FUNCTION admin.may_operate(uuid, uuid) IS
'Cet admin peut-il opérer sur ce tenant ? Vrai s''il est global, ou s''il
porte une portée vivante sur CE tenant.

p_tenant NULL ne renvoie vrai que pour un admin global : une action sans
tenant cible est par définition une action de plateforme.';

CREATE VIEW admin.effective_authority AS
SELECT u.id AS user_id,
       'PLATFORM'::text AS scope,
       NULL::uuid       AS tenant_id,
       p.granted_at, p.granted_by, p.reason
  FROM admin.platform_admin AS p
  INNER JOIN admin."user" AS u ON p.user_id = u.id
 WHERE p.revoked_at IS NULL AND u.deactivated_at IS NULL
UNION ALL
SELECT u.id, 'TENANT', t.tenant_id, t.granted_at, t.granted_by, t.reason
  FROM admin.admin_tenant AS t
  INNER JOIN admin."user" AS u ON t.user_id = u.id
 WHERE t.revoked_at IS NULL AND u.deactivated_at IS NULL;

COMMENT ON VIEW admin.effective_authority IS
'Qui peut opérer sur quoi, MAINTENANT. Un admin désactivé disparaît d''ici
sans que ses lignes d''autorité changent : la désactivation coupe l''accès,
elle ne réécrit pas l''histoire.';


-- =====================================================================
--  5. LA PRÉSENCE PORTE SA CIBLE
--
--  Sans ceci, le cloisonnement serait décoratif. Aujourd'hui un défi lie
--  une ACTION et une SESSION ; rien ne lie un tenant. Un admin du tenant A
--  obtiendrait une présence pour DELETE_DATA et la même preuve vaudrait
--  contre n'importe quel tenant.
--
--  Et l'autorité est vérifiée AU MOMENT DE CONSOMMER, pas au moment
--  d'émettre : une révocation posée entre les deux doit mordre.
-- =====================================================================

ALTER TABLE webauthn.challenge
    ADD COLUMN scope            text NOT NULL DEFAULT 'PLATFORM',
    ADD COLUMN target_tenant_id uuid;

-- Le DEFAULT n'existe que pour poser la colonne sur des lignes existantes ;
-- il part immédiatement. Un défi dont la portée serait implicite est
-- exactement ce que cette migration cherche à rendre impossible.
ALTER TABLE webauthn.challenge ALTER COLUMN scope DROP DEFAULT;

ALTER TABLE webauthn.challenge
    ADD CONSTRAINT challenge_scope
        CHECK (scope IN ('TENANT', 'PLATFORM')),
    ADD CONSTRAINT challenge_target_matches_scope CHECK (
        (scope = 'TENANT'   AND target_tenant_id IS NOT NULL)
     OR (scope = 'PLATFORM' AND target_tenant_id IS NULL));

COMMENT ON COLUMN webauthn.challenge.scope IS
'TENANT ou PLATFORM. NOT NULL sans défaut : un appelant qui oublie la portée
se fait refuser, il n''obtient pas silencieusement la plus large.';

COMMENT ON COLUMN webauthn.challenge.target_tenant_id IS
'Le tenant que cette preuve de présence autorise, et lui seul. Une présence
obtenue pour le tenant A ne consomme rien contre le tenant B.';


-- L'ancienne signature à 5 arguments est SUPPRIMÉE, pas conservée à côté.
-- La laisser vivre offrirait un chemin non scopé à tout appelant qui n'a pas
-- été mis à jour — et ce chemin serait celui qui marche encore.
DROP FUNCTION webauthn.verify_presence(bytea, text, uuid, bytea, bigint);

CREATE FUNCTION webauthn.verify_presence(
  p_challenge     bytea,
  p_action        text,
  p_session_id    uuid,
  p_credential_id bytea,
  p_sign_count    bigint,
  p_scope         text,
  p_target_tenant uuid
)
RETURNS TABLE (user_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  WITH consumed AS (
    UPDATE webauthn.challenge c
       SET consumed_at = now()
      FROM admin.session s
     WHERE c.challenge = p_challenge
       AND c.action = p_action
       AND c.session_id = p_session_id
       AND c.consumed_at IS NULL
       AND now() < c.expires_at
       -- La cible, exactement. IS NOT DISTINCT FROM parce que le cas
       -- plateforme porte NULL des deux côtés, et `NULL = NULL` ne serait
       -- jamais vrai — un admin global ne pourrait plus rien consommer.
       AND c.scope = p_scope
       AND c.target_tenant_id IS NOT DISTINCT FROM p_target_tenant
       -- L'autorité est relue ICI. Une révocation posée entre l'émission du
       -- défi et sa consommation doit invalider la preuve : sinon une portée
       -- retirée reste exploitable le temps d'un défi en vol.
       AND admin.may_operate(c.user_id, p_target_tenant)
       AND s.id = c.session_id
       AND s.ended_at IS NULL
       AND now() < s.absolute_expires_at
    RETURNING c.user_id
  )
  UPDATE webauthn.authenticator a
     SET sign_count = p_sign_count
    FROM consumed
   WHERE a.credential_id = p_credential_id
     AND a.user_id = consumed.user_id
     AND a.revoked_at IS NULL
  RETURNING a.user_id;
$$;

COMMENT ON FUNCTION webauthn.verify_presence(bytea, text, uuid, bytea, bigint, text, uuid) IS
'Consomme une preuve de présence pour une action SUR UNE CIBLE. Zéro ligne =
défi inconnu, action ou cible différente, session morte, compteur non
croissant, ou autorité révoquée depuis l''émission. Aucune de ces causes
n''est distinguée : les distinguer renseignerait l''attaquant.';


-- =====================================================================
--  6. PRIVILÈGES ET AUDIT
-- =====================================================================

GRANT SELECT ON admin.admin_tenant, admin.platform_admin,
                admin.effective_authority TO app_admin_plane;
GRANT INSERT ON admin.admin_tenant, admin.platform_admin TO app_admin_plane;
GRANT UPDATE (revoked_at, revoked_by)
   ON admin.admin_tenant, admin.platform_admin TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.may_operate(uuid, uuid) TO app_admin_plane;
GRANT EXECUTE ON FUNCTION
    webauthn.verify_presence(bytea, text, uuid, bytea, bigint, text, uuid)
    TO app_admin_plane;

REVOKE DELETE, TRUNCATE ON admin.admin_tenant, admin.platform_admin
    FROM app_admin_plane;
REVOKE ALL ON FUNCTION admin.may_operate(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION
    webauthn.verify_presence(bytea, text, uuid, bytea, bigint, text, uuid)
    FROM PUBLIC;

-- Le plus haut privilège de la plateforme doit être le mieux journalisé.
SELECT audit.watch('admin', 'admin_tenant',
       '{id, user_id, tenant_id, granted_at, granted_by, reason,
         revoked_at, revoked_by}');
SELECT audit.watch('admin', 'platform_admin',
       '{id, user_id, granted_at, granted_by, reason, revoked_at, revoked_by}');

-- La portée du défi rejoint la liste blanche ; `challenge` lui-même reste
-- hors liste, comme avant.
SELECT audit.watch('webauthn', 'challenge',
       '{id, user_id, session_id, action, scope, target_tenant_id,
         created_at, expires_at, consumed_at}');

-- Cette base a désormais un tenant. Le commentaire de la migration d'audit
-- disait « un plan de contrôle n'en a pas » — c'est devenu faux.
CREATE OR REPLACE FUNCTION audit.record()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    w          record;
    allowed    name[];
    before_row jsonb;
    after_row  jsonb;
    shape      jsonb;
    changed    jsonb := '{}'::jsonb;
    keys       jsonb := '{}'::jsonb;
    col        text;
    kc         name;
    b          jsonb;
    a          jsonb;
    raw        text;
BEGIN
    SELECT level, key_columns INTO w
      FROM audit.watched
     WHERE schema_name = TG_TABLE_SCHEMA
       AND table_name  = TG_TABLE_NAME
       AND removed_at IS NULL;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT coalesce(array_agg(column_name), '{}'::name[]) INTO allowed
      FROM audit.auditable_column
     WHERE schema_name = TG_TABLE_SCHEMA AND table_name = TG_TABLE_NAME;

    IF TG_OP = 'TRUNCATE' THEN
        INSERT INTO audit.event (actor, tenant_id, schema_name, table_name, op)
        VALUES (nullif(current_setting('app.caller', true), ''),
                nullif(current_setting('app.tenant', true), '')::uuid,
                TG_TABLE_SCHEMA, TG_TABLE_NAME, 'TRUNCATE');
        RETURN NULL;
    END IF;

    before_row := CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END;
    after_row  := CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END;
    shape      := coalesce(after_row, before_row);

    FOR col IN SELECT jsonb_object_keys(shape) LOOP
        b := before_row -> col;
        a := after_row  -> col;
        CONTINUE WHEN TG_OP = 'UPDATE' AND b IS NOT DISTINCT FROM a;

        IF col::name = ANY (allowed) THEN
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('before', b, 'after', a));
        ELSE
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('redacted', true));
        END IF;
    END LOOP;

    IF TG_OP = 'UPDATE' AND w.level = 'facts'
       AND NOT EXISTS (SELECT FROM jsonb_object_keys(changed) k
                        WHERE k::name = ANY (allowed)) THEN
        RETURN NULL;
    END IF;

    FOREACH kc IN ARRAY w.key_columns LOOP
        IF kc = ANY (allowed) THEN
            keys := keys || jsonb_build_object(kc, shape -> kc::text);
        ELSE
            raw := shape ->> kc::text;
            keys := keys || jsonb_build_object(kc,
                CASE WHEN raw IS NULL THEN NULL
                     ELSE to_jsonb('sha256:' ||
                          encode(sha256(convert_to(raw, 'UTF8')), 'hex')) END);
        END IF;
    END LOOP;

    INSERT INTO audit.event (
        actor, tenant_id, schema_name, table_name, op, row_key, changed)
    VALUES (
        nullif(current_setting('app.caller', true), ''),
        nullif(current_setting('app.tenant', true), '')::uuid,
        TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP, keys, changed);

    RETURN NULL;
END;
$$;

-- Down Migration

CREATE OR REPLACE FUNCTION audit.record()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    w          record;
    allowed    name[];
    before_row jsonb;
    after_row  jsonb;
    shape      jsonb;
    changed    jsonb := '{}'::jsonb;
    keys       jsonb := '{}'::jsonb;
    col        text;
    kc         name;
    b          jsonb;
    a          jsonb;
    raw        text;
BEGIN
    SELECT level, key_columns INTO w
      FROM audit.watched
     WHERE schema_name = TG_TABLE_SCHEMA
       AND table_name  = TG_TABLE_NAME
       AND removed_at IS NULL;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT coalesce(array_agg(column_name), '{}'::name[]) INTO allowed
      FROM audit.auditable_column
     WHERE schema_name = TG_TABLE_SCHEMA AND table_name = TG_TABLE_NAME;

    IF TG_OP = 'TRUNCATE' THEN
        INSERT INTO audit.event (actor, tenant_id, schema_name, table_name, op)
        VALUES (nullif(current_setting('app.caller', true), ''),
                NULL,
                TG_TABLE_SCHEMA, TG_TABLE_NAME, 'TRUNCATE');
        RETURN NULL;
    END IF;

    before_row := CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END;
    after_row  := CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END;
    shape      := coalesce(after_row, before_row);

    FOR col IN SELECT jsonb_object_keys(shape) LOOP
        b := before_row -> col;
        a := after_row  -> col;
        CONTINUE WHEN TG_OP = 'UPDATE' AND b IS NOT DISTINCT FROM a;
        IF col::name = ANY (allowed) THEN
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('before', b, 'after', a));
        ELSE
            changed := changed || jsonb_build_object(
                col, jsonb_build_object('redacted', true));
        END IF;
    END LOOP;

    IF TG_OP = 'UPDATE' AND w.level = 'facts'
       AND NOT EXISTS (SELECT FROM jsonb_object_keys(changed) k
                        WHERE k::name = ANY (allowed)) THEN
        RETURN NULL;
    END IF;

    FOREACH kc IN ARRAY w.key_columns LOOP
        IF kc = ANY (allowed) THEN
            keys := keys || jsonb_build_object(kc, shape -> kc::text);
        ELSE
            raw := shape ->> kc::text;
            keys := keys || jsonb_build_object(kc,
                CASE WHEN raw IS NULL THEN NULL
                     ELSE to_jsonb('sha256:' ||
                          encode(sha256(convert_to(raw, 'UTF8')), 'hex')) END);
        END IF;
    END LOOP;

    INSERT INTO audit.event (
        actor, tenant_id, schema_name, table_name, op, row_key, changed)
    VALUES (
        nullif(current_setting('app.caller', true), ''),
        NULL,   -- pas de tenant dans un plan de contrôle
        TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP, keys, changed);

    RETURN NULL;
END;
$$;

SELECT audit.watch('webauthn', 'challenge',
       '{id, user_id, session_id, action, created_at, expires_at, consumed_at}');

DELETE FROM audit.auditable_column
 WHERE schema_name = 'admin' AND table_name IN ('admin_tenant', 'platform_admin');
DELETE FROM audit.watched
 WHERE schema_name = 'admin' AND table_name IN ('admin_tenant', 'platform_admin');

DROP FUNCTION webauthn.verify_presence(bytea, text, uuid, bytea, bigint, text, uuid);

CREATE FUNCTION webauthn.verify_presence(
  p_challenge     bytea,
  p_action        text,
  p_session_id    uuid,
  p_credential_id bytea,
  p_sign_count    bigint
)
RETURNS TABLE (user_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  WITH consumed AS (
    UPDATE webauthn.challenge c
       SET consumed_at = now()
      FROM admin.session s
     WHERE c.challenge = p_challenge
       AND c.action = p_action
       AND c.session_id = p_session_id
       AND c.consumed_at IS NULL
       AND now() < c.expires_at
       AND s.id = c.session_id
       AND s.ended_at IS NULL
       AND now() < s.absolute_expires_at
    RETURNING c.user_id
  )
  UPDATE webauthn.authenticator a
     SET sign_count = p_sign_count
    FROM consumed
   WHERE a.credential_id = p_credential_id
     AND a.user_id = consumed.user_id
     AND a.revoked_at IS NULL
  RETURNING a.user_id;
$$;

GRANT EXECUTE ON FUNCTION
    webauthn.verify_presence(bytea, text, uuid, bytea, bigint) TO app_admin_plane;

ALTER TABLE webauthn.challenge
    DROP CONSTRAINT challenge_target_matches_scope,
    DROP CONSTRAINT challenge_scope,
    DROP COLUMN target_tenant_id,
    DROP COLUMN scope;

DROP VIEW admin.effective_authority;
DROP FUNCTION admin.may_operate(uuid, uuid);
DROP TABLE admin.admin_tenant;
DROP TABLE admin.platform_admin;
DROP FUNCTION admin.authority_revocation_only();
DROP FUNCTION admin.authority_no_delete();
DROP FUNCTION admin.authority_grant_guard();
