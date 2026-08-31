-- Up Migration

-- UNE ACTION SIGNÉE ÉTAIT DU TEXTE LIBRE.
--
-- `signed_command.scope` est contraint à deux valeurs, la cohérence
-- cible/portée est vérifiée, la longueur de l'empreinte aussi. `action`, non :
-- n'importe quelle chaîne passe.
--
-- `AD080` compare l'action de la commande à celle du défi et exige qu'elles
-- soient identiques — ce qui ne vaut que si les deux sont justes. Une faute de
-- frappe est reproduite à l'identique dans le défi ET dans la commande, donc
-- elle passe le contrôle et produit une PREUVE PARFAITEMENT VALIDE D'UNE ACTION
-- QUE PERSONNE N'A DÉFINIE. La relecture d'après-incident cherche
-- `tenant.terminate` et ne trouve rien, parce que la ligne dit
-- `tenant.terminat`.
--
-- Partout ailleurs dans ce dépôt un vocabulaire est une table avec
-- `deprecated_at` : motifs de révocation, fins de session, fournisseurs
-- d'identité. Cette colonne-ci était la seule exception, et c'est celle qui
-- nomme ce qu'un administrateur a fait.
--
--
-- ═══ LA PORTÉE APPARTIENT À L'ACTION, PAS À L'APPELANT ═══
--
-- `applies_to` dit sur quelle portée une action a un sens. Créer un client est
-- une action de plateforme ; usurper un utilisateur vise forcément un client.
-- L'appelant n'a donc plus à faire coïncider les deux à la main, et surtout il
-- ne peut plus déclarer une usurpation « de plateforme », qui passait
-- jusqu'ici : `signed_command_target_matches_scope` vérifiait la cohérence
-- entre `scope` et `target_tenant_id`, jamais entre `scope` et `action`.
--
-- `ANY` existe pour les actions qui se déclinent des deux côtés — l'octroi
-- d'autorité en est une, et c'est la suivante à arriver.
--
--
-- ═══ POURQUOI LE DÉFI AUSSI ═══
--
-- Le défi porte la même action, et c'est lui qui est émis EN PREMIER. Ne
-- contraindre que la commande laisserait une faute de frappe s'installer une
-- étape plus tôt, pour être refusée seulement au moment de la dépense — après
-- que l'utilisateur a touché sa clé. On refuse à l'émission.
--
--
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD061  an action is not open to this scope
--   Réutilisé : AD060 (code déprécié) via `admin.code_not_deprecated`.
-- ---------------------------------------------------------------------

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

SET ROLE admin_owner;

CREATE TABLE admin.command_action (
    code          text        NOT NULL,
    description   text        NOT NULL,
    -- 'PLATFORM', 'TENANT', ou 'ANY'.
    applies_to    text        NOT NULL,
    deprecated_at timestamptz,

    CONSTRAINT command_action_pk PRIMARY KEY (code),
    -- La même forme que partout : minuscules, points comme séparateurs. Un code
    -- lisible dans un journal sans table de correspondance.
    CONSTRAINT command_action_shape CHECK (
        code ~ '^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$'),
    CONSTRAINT command_action_applies_to CHECK (
        applies_to IN ('PLATFORM', 'TENANT', 'ANY'))
);

COMMENT ON TABLE admin.command_action IS
'Ce qu''une commande signée peut prétendre faire. Une table et non du texte
libre : une faute de frappe produisait une preuve valide d''une action que
personne n''a définie, et se reproduisait à l''identique dans le défi, donc
AD080 ne la voyait pas.';

COMMENT ON COLUMN admin.command_action.applies_to IS
'Sur quelle portée cette action a un sens. Créer un client est une action de
plateforme ; usurper vise forcément un client. Ce que la contrainte de portée
ne pouvait pas dire : elle liait `scope` à `target_tenant_id`, jamais à
l''action.';

COMMENT ON COLUMN admin.command_action.deprecated_at IS
'Retirée des NOUVELLES écritures (AD060), lisible pour toujours sur les
commandes qui la portent. On ne réécrit pas ce qu''un administrateur a fait
parce qu''on a renommé le geste depuis.';

INSERT INTO admin.command_action (code, description, applies_to) VALUES
  ('tenant.create',      'Provisionner un client.',                'PLATFORM'),
  ('tenant.suspend',     'Suspendre un client.',                   'TENANT'),
  ('tenant.lift',        'Lever la suspension d''un client.',      'TENANT'),
  ('tenant.terminate',   'Résilier un client — sens unique.',      'TENANT'),
  ('tenant.impersonate', 'Prendre la place d''un utilisateur.',    'TENANT'),
  ('authority.grant',    'Accorder une autorité d''administration.', 'ANY'),
  ('authority.revoke',   'Révoquer une autorité d''administration.', 'ANY'),
  ('identity.provision', 'Provisionner un compte d''administration.', 'PLATFORM'),
  ('sso.declare',        'Déclarer ou modifier une connexion SSO.',  'TENANT'),
  ('iam.define',         'Créer ou modifier un rôle, un périmètre.', 'TENANT');

CREATE VIEW api.command_action AS
  SELECT code, description, applies_to, deprecated_at FROM admin.command_action;

GRANT SELECT ON api.command_action TO app_admin_plane;

-- Surveillée comme les deux autres vocabulaires : déprécier une action est une
-- décision de gouvernance, pas de l'entretien. La suite de tests refuse
-- d'ailleurs qu'une table de cette base échappe à l'audit sans plaider son cas.
SELECT audit.watch('admin', 'command_action',
       '{code, description, applies_to, deprecated_at}');

-- Le vocabulaire ne se supprime pas, il se déprécie. Sinon une commande
-- historique perdrait le nom de ce qu'elle a fait.
CREATE TRIGGER command_action_no_delete
    BEFORE DELETE ON admin.command_action
    FOR EACH ROW EXECUTE FUNCTION admin.no_delete();


-- =====================================================================
--  L'ACTION CODÉE EN DUR DEVIENT UNE LIGNE
-- =====================================================================

-- `impersonation_guard` comparait l'action de la commande au littéral
-- `'impersonate'`, au milieu d'une fonction. Elle devient `tenant.impersonate`,
-- nommée comme les autres et présente dans une table — un littéral survit à un
-- renommage sans rien dire, une clé étrangère non.
--
-- AVANT les clés étrangères : les lignes déjà écrites les violeraient.
UPDATE webauthn.challenge   SET action = 'tenant.impersonate'
 WHERE action = 'impersonate';
UPDATE admin.signed_command SET action = 'tenant.impersonate'
 WHERE action = 'impersonate';

-- =====================================================================
--  CE QUI EST DÉJÀ ÉCRIT DOIT ÊTRE DANS LE VOCABULAIRE
-- =====================================================================

-- La clé étrangère refuserait les lignes existantes avec le message générique
-- de Postgres — le nom d'une contrainte, pas la valeur fautive. On les nomme
-- avant, et on refuse de deviner : inventer l'action d'une commande déjà
-- signée, c'est réécrire ce qu'un administrateur a fait.
DO $$
DECLARE
    strays text;
BEGIN
    SELECT string_agg(DISTINCT a, ', ') INTO strays
      FROM (SELECT action AS a FROM webauthn.challenge
            UNION SELECT action FROM admin.signed_command) t
     WHERE NOT EXISTS (
        SELECT FROM admin.command_action c WHERE c.code = t.a);

    IF strays IS NOT NULL THEN
        RAISE EXCEPTION
            'these actions are already written and are not in the vocabulary: %',
            strays
            USING HINT =
                'Declare them in admin.command_action with the scope they apply '
                'to, or correct them, before replaying this migration. Guessing '
                'what a signed command meant is rewriting what an admin did.';
    END IF;
END $$;


-- =====================================================================
--  LES DEUX TABLES QUI NOMMENT UNE ACTION
-- =====================================================================

ALTER TABLE webauthn.challenge
    ADD CONSTRAINT challenge_action_fk
    FOREIGN KEY (action) REFERENCES admin.command_action (code)
    ON DELETE RESTRICT;

ALTER TABLE admin.signed_command
    ADD CONSTRAINT signed_command_action_fk
    FOREIGN KEY (action) REFERENCES admin.command_action (code)
    ON DELETE RESTRICT;

CREATE TRIGGER challenge_action_not_deprecated
    BEFORE INSERT OR UPDATE OF action ON webauthn.challenge
    FOR EACH ROW EXECUTE FUNCTION
        admin.code_not_deprecated('action', 'admin.command_action');

CREATE TRIGGER signed_command_action_not_deprecated
    BEFORE INSERT OR UPDATE OF action ON admin.signed_command
    FOR EACH ROW EXECUTE FUNCTION
        admin.code_not_deprecated('action', 'admin.command_action');


-- =====================================================================
--  L'ACTION DÉCIDE DE LA PORTÉE
-- =====================================================================

CREATE FUNCTION admin.action_fits_scope()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_applies text;
BEGIN
    SELECT applies_to INTO v_applies
      FROM admin.command_action WHERE code = NEW.action;

    -- Introuvable : la clé étrangère va parler, et elle le dira mieux.
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF v_applies <> 'ANY' AND v_applies <> NEW.scope THEN
        RAISE EXCEPTION 'action % applies to %, not to %',
            NEW.action, v_applies, NEW.scope
            USING ERRCODE = 'AD061',
                  HINT = 'The scope belongs to the action, not to the caller. '
                         'Declaring an impersonation as a platform action was '
                         'accepted until this constraint existed.';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE EXECUTE ON FUNCTION admin.action_fits_scope() FROM PUBLIC;

COMMENT ON FUNCTION admin.action_fits_scope IS
'La portée appartient à l''action. `signed_command_target_matches_scope` liait
`scope` à `target_tenant_id` ; rien ne liait `scope` à ce qu''on prétendait
faire, donc une usurpation « de plateforme » passait.';

CREATE TRIGGER challenge_action_fits_scope
    BEFORE INSERT OR UPDATE OF action, scope ON webauthn.challenge
    FOR EACH ROW EXECUTE FUNCTION admin.action_fits_scope();

CREATE TRIGGER signed_command_action_fits_scope
    BEFORE INSERT OR UPDATE OF action, scope ON admin.signed_command
    FOR EACH ROW EXECUTE FUNCTION admin.action_fits_scope();

CREATE OR REPLACE FUNCTION admin.impersonation_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    cap interval;
BEGIN
    PERFORM FROM admin.signed_command c
     WHERE c.id = NEW.command_id
       AND c.action = 'tenant.impersonate'
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

    SELECT max(s.max_impersonation) INTO cap
      FROM admin.effective_authority e
      JOIN admin.authority_scope s ON s.scope = e.scope
     WHERE e.user_id = NEW.operator_user_id
       AND (e.scope = 'PLATFORM' OR e.tenant_id = NEW.target_tenant_id);

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

RESET ROLE;

-- Down Migration

SET ROLE admin_owner;

CREATE OR REPLACE FUNCTION admin.impersonation_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    cap interval;
BEGIN
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

    SELECT max(s.max_impersonation) INTO cap
      FROM admin.effective_authority e
      JOIN admin.authority_scope s ON s.scope = e.scope
     WHERE e.user_id = NEW.operator_user_id
       AND (e.scope = 'PLATFORM' OR e.tenant_id = NEW.target_tenant_id);

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

DROP TRIGGER signed_command_action_fits_scope ON admin.signed_command;
DROP TRIGGER challenge_action_fits_scope ON webauthn.challenge;
DROP FUNCTION admin.action_fits_scope();

DROP TRIGGER signed_command_action_not_deprecated ON admin.signed_command;
DROP TRIGGER challenge_action_not_deprecated ON webauthn.challenge;

ALTER TABLE admin.signed_command DROP CONSTRAINT signed_command_action_fk;
ALTER TABLE webauthn.challenge   DROP CONSTRAINT challenge_action_fk;

DROP VIEW api.command_action;

DELETE FROM audit.watched
 WHERE schema_name = 'admin' AND table_name = 'command_action';

ALTER TABLE admin.command_action DISABLE TRIGGER command_action_no_delete;
DROP TABLE admin.command_action;

UPDATE webauthn.challenge   SET action = 'impersonate'
 WHERE action = 'tenant.impersonate';
UPDATE admin.signed_command SET action = 'impersonate'
 WHERE action = 'tenant.impersonate';

RESET ROLE;
