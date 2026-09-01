-- Up Migration

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

-- =====================================================================
-- Vocabulary out of the type system and into data — the control plane's
-- half of the same change. See the auth migration for the reasoning.
--
-- akeys.key_state stays an enum: PENDING/ACTIVE is a state machine, not
-- vocabulary. It has exactly the values the protocol has, and it will
-- never accumulate a third that someone later wishes they could remove.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY (this migration)
--   RAISED by triggers (custom SQLSTATE):
--     AD060  a deprecated code may not be used on a new write
-- ---------------------------------------------------------------------

-- ---------------------------------------------------------------------
-- 1. Detach the columns from the types.
-- ---------------------------------------------------------------------
DROP VIEW api.live_pair;
DROP VIEW api.live_session;
DROP VIEW api.session;
DROP VIEW api.identity;
DROP VIEW admin.live_pair;
DROP VIEW admin.live_session;

-- The DEFAULT carries the type, so it goes before the type can.
ALTER TABLE admin.session
  ALTER COLUMN end_reason DROP DEFAULT,
  ALTER COLUMN end_reason TYPE text USING end_reason::text;
ALTER TABLE admin.identity
  ALTER COLUMN provider DROP DEFAULT,
  ALTER COLUMN provider TYPE text USING provider::text;

DROP TYPE admin.session_end_reason;
DROP TYPE admin.identity_provider;

-- ---------------------------------------------------------------------
-- 2. The vocabulary, as rows.
-- ---------------------------------------------------------------------
CREATE TABLE admin.session_end_reason (
  code          text PRIMARY KEY,
  description   text NOT NULL,
  deprecated_at timestamptz,
  CONSTRAINT session_end_reason_code_shape CHECK (code ~ '^[A-Z][A-Z_]{2,31}$')
);

COMMENT ON TABLE admin.session_end_reason IS
  'Why a control-plane session ended. A row rather than an enum label, so a code can be retired without rewriting the sessions that carry it. Append-only like everything else here: you deprecate a code, you never delete it.';

INSERT INTO admin.session_end_reason (code, description) VALUES
  ('LOGOUT',     'Explicit logout.'),
  ('EXPIRED',    'Inactivity window or absolute ceiling reached.'),
  ('SUPERSEDED', 'A newer session for the same admin (mono-session).'),
  ('SECURITY',   'Refresh replay detected.');

CREATE TABLE admin.identity_provider (
  code          text PRIMARY KEY,
  description   text NOT NULL,
  deprecated_at timestamptz,
  CONSTRAINT identity_provider_code_shape CHECK (code ~ '^[A-Z][A-Z0-9_]{1,31}$')
);

COMMENT ON TABLE admin.identity_provider IS
  'Identity providers the privileged plane accepts. One row today; the point is that retiring it one day does not require reaching into a type definition while admins are bound through it.';

INSERT INTO admin.identity_provider (code, description) VALUES
  ('ENTRA', 'Microsoft Entra ID, behind a dedicated enterprise application.');

-- ---------------------------------------------------------------------
-- 3. Referential integrity replaces type checking.
-- ---------------------------------------------------------------------
ALTER TABLE admin.session
  ADD CONSTRAINT session_end_reason_fkey
  FOREIGN KEY (end_reason) REFERENCES admin.session_end_reason (code)
  ON DELETE RESTRICT;

-- The default is restored: unlike auth, this column always had one, and a
-- migration that removes it would be a behaviour change in the other direction.
ALTER TABLE admin.identity
  ALTER COLUMN provider SET DEFAULT 'ENTRA',
  ADD CONSTRAINT identity_provider_fkey
  FOREIGN KEY (provider) REFERENCES admin.identity_provider (code)
  ON DELETE RESTRICT;

-- ---------------------------------------------------------------------
-- 4. Deprecation has to bite.
-- ---------------------------------------------------------------------
CREATE FUNCTION admin.code_not_deprecated() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_col text := TG_ARGV[0];
  v_ref text := TG_ARGV[1];
  v_new text;
  v_old text;
  v_dep timestamptz;
BEGIN
  EXECUTE format('SELECT ($1).%I', v_col) INTO v_new USING NEW;
  IF v_new IS NULL THEN
    RETURN NEW;
  END IF;

  -- Only when the value CHANGES: deprecation retires vocabulary, it does not
  -- freeze the rows that used it.
  IF TG_OP = 'UPDATE' THEN
    EXECUTE format('SELECT ($1).%I', v_col) INTO v_old USING OLD;
    IF v_new IS NOT DISTINCT FROM v_old THEN
      RETURN NEW;
    END IF;
  END IF;

  EXECUTE format('SELECT deprecated_at FROM %s WHERE code = $1', v_ref)
    INTO v_dep USING v_new;
  IF v_dep IS NOT NULL AND v_dep <= now() THEN
    RAISE EXCEPTION '%.%: code % has been deprecated since %',
      TG_TABLE_SCHEMA, TG_TABLE_NAME, v_new, v_dep
      USING ERRCODE = 'AD060';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION admin.code_not_deprecated IS
  'Refuses a retired code on a NEW write (AD060). Generic over (column, reference table) through TG_ARGV, so retiring vocabulary costs one CREATE TRIGGER.';

CREATE TRIGGER session_end_reason_not_deprecated
  BEFORE INSERT OR UPDATE OF end_reason ON admin.session
  FOR EACH ROW EXECUTE FUNCTION
    admin.code_not_deprecated('end_reason', 'admin.session_end_reason');

CREATE TRIGGER identity_provider_not_deprecated
  BEFORE INSERT OR UPDATE OF provider ON admin.identity
  FOR EACH ROW EXECUTE FUNCTION
    admin.code_not_deprecated('provider', 'admin.identity_provider');

-- The vocabulary is append-only, like every other table in this schema.
CREATE TRIGGER no_delete_end_reason BEFORE DELETE ON admin.session_end_reason
  FOR EACH ROW EXECUTE FUNCTION admin.no_delete();
CREATE TRIGGER no_delete_provider   BEFORE DELETE ON admin.identity_provider
  FOR EACH ROW EXECUTE FUNCTION admin.no_delete();

-- ---------------------------------------------------------------------
-- 5. Rebuild the contract, unchanged in shape.
-- ---------------------------------------------------------------------
CREATE VIEW admin.live_session
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, created_at, absolute_expires_at, ended_at, end_reason
    FROM admin.session
   WHERE ended_at IS NULL AND now() < absolute_expires_at;
COMMENT ON VIEW admin.live_session IS
  'A session is live only within its 1 h absolute ceiling. Past it, it is dead even without an explicit ended_at — expiry is derived from now(), never a cron.';

CREATE VIEW admin.live_pair
    WITH (security_invoker = TRUE)
AS
  SELECT p.id, p.session_id, p.jti_bearer, p.jti_refresh, p.issued_at,
         p.inactivity_expires_at, p.replaced_at
  FROM admin.token_pair AS p
  INNER JOIN admin.live_session AS s ON p.session_id = s.id
  WHERE p.replaced_at IS NULL AND now() < p.inactivity_expires_at;
COMMENT ON VIEW admin.live_pair IS
  'A pair is refreshable only if not replaced, within its 15 min inactivity window, AND its session is within the 1 h ceiling. Both bounds, derived from now().';

CREATE VIEW api.session
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, created_at, absolute_expires_at, ended_at, end_reason
    FROM admin.session;
CREATE VIEW api.identity
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, provider, provider_id, provision_key, created_at, bound_at
    FROM admin.identity;
CREATE VIEW api.live_session
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, created_at, absolute_expires_at, ended_at, end_reason
    FROM admin.live_session;
CREATE VIEW api.live_pair
    WITH (security_invoker = TRUE)
AS
  SELECT id, session_id, jti_bearer, jti_refresh, issued_at, inactivity_expires_at,
         replaced_at
    FROM admin.live_pair;

CREATE VIEW api.session_end_reason AS
  SELECT code, description, deprecated_at FROM admin.session_end_reason;
CREATE VIEW api.identity_provider AS
  SELECT code, description, deprecated_at FROM admin.identity_provider;

GRANT SELECT, INSERT ON api.session TO app_admin_plane;
GRANT UPDATE (ended_at, end_reason) ON api.session TO app_admin_plane;
GRANT SELECT, INSERT ON api.identity TO app_admin_plane;
GRANT UPDATE (provider_id, provision_key) ON api.identity TO app_admin_plane;
GRANT SELECT ON api.live_session, api.live_pair TO app_admin_plane;
GRANT SELECT ON api.session_end_reason, api.identity_provider TO app_admin_plane;

-- Down Migration

DROP VIEW api.identity_provider;
DROP VIEW api.session_end_reason;
DROP VIEW api.live_pair;
DROP VIEW api.live_session;
DROP VIEW api.identity;
DROP VIEW api.session;
DROP VIEW admin.live_pair;
DROP VIEW admin.live_session;

DROP TRIGGER no_delete_provider ON admin.identity_provider;
DROP TRIGGER no_delete_end_reason ON admin.session_end_reason;
DROP TRIGGER identity_provider_not_deprecated ON admin.identity;
DROP TRIGGER session_end_reason_not_deprecated ON admin.session;
DROP FUNCTION admin.code_not_deprecated();

ALTER TABLE admin.identity
  DROP CONSTRAINT identity_provider_fkey,
  ALTER COLUMN provider DROP DEFAULT;
ALTER TABLE admin.session DROP CONSTRAINT session_end_reason_fkey;

DROP TABLE admin.identity_provider;
DROP TABLE admin.session_end_reason;

CREATE TYPE admin.identity_provider AS ENUM ('ENTRA');
CREATE TYPE admin.session_end_reason AS ENUM
  ('LOGOUT', 'EXPIRED', 'SUPERSEDED', 'SECURITY');

ALTER TABLE admin.session
  ALTER COLUMN end_reason TYPE admin.session_end_reason
  USING end_reason::admin.session_end_reason;
ALTER TABLE admin.identity
  ALTER COLUMN provider TYPE admin.identity_provider
  USING provider::admin.identity_provider,
  ALTER COLUMN provider SET DEFAULT 'ENTRA';

CREATE VIEW admin.live_session
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, created_at, absolute_expires_at, ended_at, end_reason
    FROM admin.session
   WHERE ended_at IS NULL AND now() < absolute_expires_at;
CREATE VIEW admin.live_pair
    WITH (security_invoker = TRUE)
AS
  SELECT p.id, p.session_id, p.jti_bearer, p.jti_refresh, p.issued_at,
         p.inactivity_expires_at, p.replaced_at
  FROM admin.token_pair AS p
  INNER JOIN admin.live_session AS s ON p.session_id = s.id
  WHERE p.replaced_at IS NULL AND now() < p.inactivity_expires_at;
CREATE VIEW api.session
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, created_at, absolute_expires_at, ended_at, end_reason
    FROM admin.session;
CREATE VIEW api.identity
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, provider, provider_id, provision_key, created_at, bound_at
    FROM admin.identity;
CREATE VIEW api.live_session
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, created_at, absolute_expires_at, ended_at, end_reason
    FROM admin.live_session;
CREATE VIEW api.live_pair
    WITH (security_invoker = TRUE)
AS
  SELECT id, session_id, jti_bearer, jti_refresh, issued_at, inactivity_expires_at,
         replaced_at
    FROM admin.live_pair;

GRANT SELECT, INSERT ON api.session TO app_admin_plane;
GRANT UPDATE (ended_at, end_reason) ON api.session TO app_admin_plane;
GRANT SELECT, INSERT ON api.identity TO app_admin_plane;
GRANT UPDATE (provider_id, provision_key) ON api.identity TO app_admin_plane;
GRANT SELECT ON api.live_session, api.live_pair TO app_admin_plane;
