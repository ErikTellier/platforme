-- Up Migration

-- Un verrou ne s'attend pas : une migration qui pend bloque tout (CLAUDE.md).
SET LOCAL lock_timeout     = '3s';
SET LOCAL statement_timeout = '60s';

-- =====================================================================
-- ADMIN: privileged control plane
-- Target: PostgreSQL 16+
--
-- Same doctrine as auth/iam: store FACTS and DECISIONS, never states.
-- States derive from now() through views. Invariants live in the DDL.
-- The application is an ADAPTER. No cron: everything is lazy.
--
-- ---------------------------------------------------------------------
-- WHAT ADMIN IS
--   A sovereign, privileged CONTROL PLANE — distinct from:
--     auth  (who are you — managers, per tenant)
--     iam   (what may you do — inside a tenant)
--     admin (who may RECONFIGURE THE PLATFORM ITSELF)
--   Admin owns NO business data. It ORCHESTRATES: it emits signed
--   commands to sovereign services (auth today, feature-flags tomorrow),
--   which execute and emit their own events. Admin down -> no admin
--   actions, nothing else. Services checking admin eligibility fail CLOSED.
--
-- ---------------------------------------------------------------------
-- TWO SUPERPOSED LAYERS OF SECURITY (both required for a heavy action)
--
--   Layer 1 — IDENTITY (Entra SSO -> admin session)
--     "This is admin X, authenticated via Entra."
--     A bearer/refresh pair, SHORT:
--       bearer  : 5 min
--       refresh : 15 min inactivity  AND  1 h absolute ceiling
--     Non-prolongable past the absolute ceiling: re-login via Entra.
--     Entra access is itself gated by a dedicated ENTERPRISE APPLICATION
--     restricted to admins (first filter, at the IdP, before any code).
--     NO tenant, NO membership, NO tenant switch — admin is ABOVE tenants.
--
--   Layer 2 — PRESENCE (WebAuthn / FIDO2, native)
--     "It is really me, in front of the machine, NOW."
--     A hardware touch, per HEAVY action. Short-lived, single-use.
--     Proof gates the TRIGGERING of an action; it never interrupts a
--     composition in progress (select 150 users freely, prove once at
--     the validation click).
--
-- ---------------------------------------------------------------------
-- SIGNED COMMANDS — the cryptographic heart
--   A heavy action becomes a command SIGNED by the admin's OWN key,
--   then sent (gRPC) to the sovereign service, which verifies it with
--   the admin's PUBLIC key — LOCALLY, without calling back admin
--   (decentralized verification: admin down does not break in-flight
--   command verification).
--
--   ONE SIGNING KEY PER ADMIN (2-3 admins, ever). The signature does
--   not merely attest "an admin validated" but "THIS admin validated" —
--   cryptographic, individual NON-REPUDIATION, verifiable months later.
--   kid -> admin_id must be resolvable, so the signature carries the actor.
--
--   The key is ROTATED AT LOGIN and lives exactly one session (1 h):
--     signs_until     = login + 1 h        (may sign until then)
--     published_until = signs_until + 10m  (verifiable a bit longer,
--                       to cover a command signed at minute 59 that
--                       reaches the service at minute 61 — retry, queue,
--                       slight async). Verification != signing.
--
--   Audit of signed commands does NOT live here: no table. The event
--   goes to a DEDICATED admin SIEM stream (admin is a producer). The
--   signed command is its own proof (signature + kid + nonce + time);
--   the immutable archive is the SIEM, not a table someone could alter.
--
-- ---------------------------------------------------------------------
-- ERROR CODE REGISTRY
--   An invariant surfaces in exactly one of three ways: RAISED with a custom
--   SQLSTATE, returned as ZERO ROWS, or caught by a standard constraint.
--   Nothing is declared here that the DDL below does not actually produce.
--
--   RAISED by triggers (custom SQLSTATE):
--     AD001  session: emission refused, admin inactive/unknown
--     AD002  token_pair: incoherent pair (jti_bearer = jti_refresh)
--     AD003  token_pair: emission refused, the admin has been deactivated
--     AD010  token_pair: emission past the session absolute ceiling (1 h)
--     AD012  token_pair: emission on a session that is missing or already ended
--     AD013  token_pair: inactivity window exceeds the session ceiling
--     AD021  key: irreversible fact re-posted (destroyed_at, ACTIVE -> PENDING)
--     AD022  key: signs_until exceeds the session absolute ceiling
--     AD031  webauthn: sign_count did not strictly increase (possible clone)
--     AD040  append-only: DELETE forbidden
--     AD050  identity: provider_id is immutable once bound (rebind attempt)
--
--   ZERO ROWS, never an exception. Atomic consumption returns nothing rather
--   than raising, so the caller never needs a SELECT to decide (that SELECT
--   would be the race). The caller maps zero rows to its own refusal:
--     admin.consume_pair()         -> 0 rows = replay, inactivity window
--                                     exceeded, or session ceiling reached
--     admin.rotate_pair()          -> same, and emits the successor in the
--                                     same statement (raises AD003 instead if
--                                     the admin has been deactivated)
--     webauthn.verify_presence()   -> 0 rows = unknown challenge, wrong action,
--                                     wrong session, already consumed, expired,
--                                     or the authenticator does not match
--     admin.validate_bearer()      -> 0 rows = bearer not usable right now
--                                     (rotated, session dead, admin deactivated)
--
--   STANDARD codes, enforced by constraints rather than by triggers:
--     23505  unique_violation — mono-session (uq_session_mono), one live pair
--            per session, one ACTIVE key per admin, jti reuse
--     23514  check_violation — domains (uuid_v4) and coherence CHECKs
--     23503  foreign_key_violation — a key whose session belongs to another admin
--     42501  insufficient_privilege — grant map violations
--
-- ---------------------------------------------------------------------
-- NOTE: no explicit BEGIN/COMMIT — node-pg-migrate opens the transaction.
--
-- Beware of WHAT it wraps: the WHOLE RUN, not one migration at a time. That
-- is the default (`--single-transaction` defaults to true), and it differs
-- from goose, which committed each file on its own. A failure on the last
-- file therefore rolls back every earlier one. Seen while porting these
-- migrations: a failure on the 24th left `pgmigrations` empty.
--
-- No statement fencing here. These files were written for goose, which
-- splits on semicolons and needed its StatementBegin/End annotations around
-- any dollar-quoted body. node-pg-migrate splits nothing — it hands the
-- whole block to `pgm.sql()` — so the annotations were dropped in the port.
--
-- The trap changed shape rather than disappeared. Its own markers are
-- `-- Up Migration` and `-- Down Migration`, matched case-insensitively
-- ANYWHERE in the file, and the FIRST match wins. A prose line that happens
-- to read like one would cut the migration in half. Do not write them out.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Schemas
-- ---------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS admin;
CREATE SCHEMA IF NOT EXISTS webauthn;
CREATE SCHEMA IF NOT EXISTS akeys;   -- admin signing keys (JWKS)

COMMENT ON SCHEMA admin    IS 'Privileged control plane: identity, sessions, orchestration. Owns no business data.';
COMMENT ON SCHEMA webauthn IS 'Presence layer: native WebAuthn authenticators and challenges.';
COMMENT ON SCHEMA akeys    IS 'Per-admin signing keys. One live signing key per admin, rotated at login, lives one session.';

-- ---------------------------------------------------------------------
-- 1. Extensions, domains & types
-- ---------------------------------------------------------------------
-- provision_key is a human-typed UPN: its case is noise, never meaning.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE DOMAIN admin.uuid_v4 AS uuid
  CHECK (
    (VALUE::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  );
COMMENT ON DOMAIN admin.uuid_v4 IS
  'Rejects a non-v4 UUID. External ids (Entra oid) are not v4 and live in identity, not here.';

-- Single-value enum = allowlist, same doctrine as jwks.key_alg: adding a
-- provider to the privileged plane is a conscious MIGRATION, never a string
-- someone types. As free text, 'ENTRA' / 'Entra' / 'entra' would be three
-- distinct providers sharing one unique index.
CREATE TYPE admin.identity_provider AS ENUM ('ENTRA');

CREATE TYPE admin.session_end_reason AS ENUM (
  'LOGOUT',        -- explicit
  'EXPIRED',       -- inactivity or absolute ceiling
  'SUPERSEDED',    -- a newer session for the same admin (mono-session)
  'SECURITY'       -- refresh replay detected
);

CREATE TYPE akeys.key_state AS ENUM ('PENDING', 'ACTIVE');

-- ---------------------------------------------------------------------
-- 2. Admin identity — decal of auth, WITHOUT tenant. Ultra-restricted
--    provisioning: an admin is explicitly declared, never self-created.
-- ---------------------------------------------------------------------
CREATE TABLE admin."user" (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at     timestamptz NOT NULL DEFAULT now(),
  deactivated_at timestamptz
);
COMMENT ON TABLE admin."user" IS
  'A platform administrator. Pseudonymous (no PII — that lives in identity). 2-3 rows, ever. Deactivation is a dated fact; never deleted (signed commands and audit reference this id).';

CREATE TABLE admin.identity (
  id            uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES admin."user"(id) ON DELETE RESTRICT,
  provider      admin.identity_provider NOT NULL DEFAULT 'ENTRA',
  provider_id   text,                       -- Entra oid, captured on first login
  provision_key citext,                     -- UPN, used once to bind, then nulled
  created_at    timestamptz NOT NULL DEFAULT now(),
  bound_at      timestamptz,
  CONSTRAINT identity_provider_or_provision
    CHECK (provider_id IS NOT NULL OR provision_key IS NOT NULL),
  -- bound_at is not decoration: it is set if and only if the identity is
  -- bound. The trigger stamps it; this CHECK stops anyone unstamping it.
  CONSTRAINT identity_bound_coherent
    CHECK ((provider_id IS NULL) = (bound_at IS NULL))
);

-- One identity per (admin, provider): an admin has a single Entra account,
-- so a second binding is a provisioning error, not a second way in.
CREATE UNIQUE INDEX uq_identity_user_provider
  ON admin.identity (user_id, provider);
CREATE UNIQUE INDEX uq_identity_provider_id
  ON admin.identity (provider, provider_id) WHERE provider_id IS NOT NULL;
CREATE UNIQUE INDEX uq_identity_provision_key
  ON admin.identity (provider, provision_key) WHERE provision_key IS NOT NULL;

COMMENT ON TABLE admin.identity IS
  'Binds an Entra account to an admin user. First login captures the stable oid into provider_id and nulls provision_key. The dedicated Entra enterprise application is the first filter — only its members ever reach this flow.';
COMMENT ON COLUMN admin.identity.provider_id IS
  'Entra oid — case-SENSITIVE (never citext), and IMMUTABLE once bound (trigger identity_bind_once, AD050). Rebinding it would reattribute every future signature of this admin, so it is refused even to app_admin_plane: the cryptographic non-repudiation of akeys.key is only worth what this column is worth.';
COMMENT ON COLUMN admin.identity.provision_key IS
  'Admin-typed matching key (UPN) used once, at first login — EPHEMERAL PII, nullified upon provider_id capture. citext: this is provisioned by hand, and the case of an email address is human noise, not identity.';
COMMENT ON COLUMN admin.identity.bound_at IS
  'The instant provider_id was captured. Derived by the trigger, not trusted from the caller — which is why app_admin_plane has no UPDATE grant on it.';

-- ---------------------------------------------------------------------
-- 3. Sessions — bearer/refresh (Layer 1), short, non-prolongable past 1 h
-- ---------------------------------------------------------------------
CREATE TABLE admin.session (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              uuid NOT NULL REFERENCES admin."user"(id) ON DELETE RESTRICT,
  created_at           timestamptz NOT NULL DEFAULT now(),
  absolute_expires_at  timestamptz NOT NULL,     -- created_at + 1 h, HARD ceiling
  ended_at             timestamptz,
  end_reason           admin.session_end_reason,
  CONSTRAINT session_end_coherent
    CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
  CONSTRAINT session_absolute_after_creation
    CHECK (absolute_expires_at > created_at),
  -- Target for the composite FK from akeys.key: a key's admin and its
  -- session's admin must be the SAME. Without this, a key could claim
  -- admin A while pointing at admin B's session (attribution laundering).
  CONSTRAINT session_id_user_unique UNIQUE (id, user_id)
);

CREATE INDEX ix_session_user_live
  ON admin.session (user_id) WHERE ended_at IS NULL;

-- MONO-SESSION, enforced by the ENGINE and not merely by the trigger.
-- session_supersede ends the previous live session BEFORE INSERT, but a
-- trigger only ever sees COMMITTED rows: two concurrent logins would each
-- miss the other's uncommitted session and both would stay live. This
-- partial unique index closes that race — the loser gets 23505.
CREATE UNIQUE INDEX uq_session_mono
  ON admin.session (user_id) WHERE ended_at IS NULL;

COMMENT ON TABLE admin.session IS
  'Layer-1 identity session. absolute_expires_at is the 1 h ceiling set at login — a session is NEVER prolonged past it; the admin re-logs via Entra. Mono-session: opening a new one SUPERSEDES the previous (BEFORE INSERT trigger), and uq_session_mono makes that hold under concurrency.';
COMMENT ON INDEX admin.uq_session_mono IS
  'At most one live session per admin, guaranteed by the engine. The supersede trigger is the ergonomics; this index is the invariant.';
COMMENT ON COLUMN admin.session.absolute_expires_at IS
  'HARD ceiling = created_at + 1 h. The refresh path refuses past it (AD010), regardless of activity.';

-- The bearer/refresh pair history. One live pair per session; rotation
-- consumes the old and emits the new atomically (as in auth). The
-- refresh also carries the 15 min INACTIVITY window.
CREATE TABLE admin.token_pair (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id        uuid NOT NULL REFERENCES admin.session(id) ON DELETE RESTRICT,
  jti_bearer        admin.uuid_v4 NOT NULL,
  jti_refresh       admin.uuid_v4 NOT NULL,
  issued_at         timestamptz NOT NULL DEFAULT now(),
  inactivity_expires_at timestamptz NOT NULL,     -- issued_at + 15 min
  replaced_at       timestamptz,
  CONSTRAINT pair_inactivity_after_issue
    CHECK (inactivity_expires_at > issued_at)
);

CREATE UNIQUE INDEX uq_pair_bearer  ON admin.token_pair (jti_bearer);
CREATE UNIQUE INDEX uq_pair_refresh ON admin.token_pair (jti_refresh);
-- One live pair per session (mono-active pair). The partial unique index
-- makes a second live pair for the same session impossible.
CREATE UNIQUE INDEX uq_pair_live_per_session
  ON admin.token_pair (session_id) WHERE replaced_at IS NULL;

CREATE INDEX ix_pair_session ON admin.token_pair (session_id);

COMMENT ON TABLE admin.token_pair IS
  'bearer 5 min / refresh renewable within 15 min inactivity. Rotation = consume old (replaced_at) + emit new, atomically. A replayed refresh (two consumptions of the same pair) kills the session (SECURITY) — same mechanism as auth.';
COMMENT ON COLUMN admin.token_pair.inactivity_expires_at IS
  'issued_at + 15 min. Never raised as an error: admin.consume_pair() simply returns zero rows past it. Combined with the session absolute ceiling, a refresh succeeds only if now() < inactivity_expires_at AND now() < session.absolute_expires_at — both checked in the same statement.';

-- ---------------------------------------------------------------------
-- 4. WebAuthn — the presence layer (Layer 2)
-- ---------------------------------------------------------------------
CREATE TABLE webauthn.authenticator (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid NOT NULL REFERENCES admin."user"(id) ON DELETE RESTRICT,
  credential_id  bytea NOT NULL,            -- the WebAuthn credential id (raw)
  public_key     bytea NOT NULL,            -- COSE public key
  sign_count     bigint NOT NULL DEFAULT 0, -- anti-clone counter
  label          text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz
);

CREATE UNIQUE INDEX uq_authenticator_credential
  ON webauthn.authenticator (credential_id);
CREATE INDEX ix_authenticator_user
  ON webauthn.authenticator (user_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE webauthn.authenticator IS
  'A registered FIDO2 authenticator (hardware key). sign_count must be strictly increasing across assertions: a regression means a possible cloned key (AD031). Native WebAuthn — the presence challenge is redeemed locally, no Entra redirect.';
COMMENT ON COLUMN webauthn.authenticator.sign_count IS
  'Signature counter from the authenticator. Each assertion must present a count strictly greater than the stored one; otherwise the credential may be cloned and the assertion is refused.';

CREATE TABLE webauthn.challenge (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES admin."user"(id) ON DELETE RESTRICT,
  session_id   uuid NOT NULL,
  challenge    bytea NOT NULL,
  action       text NOT NULL,              -- the heavy action this presence gates
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,       -- short: a couple of minutes
  consumed_at  timestamptz,
  CONSTRAINT challenge_expiry_after_creation
    CHECK (expires_at > created_at),
  -- Composite FK, same anti-laundering trick as akeys.key: the challenge's
  -- admin and its session's admin must be the SAME. A presence proof is bound
  -- to the session that asked for it, so it cannot be collected under one
  -- session and spent under another — and a re-login (which supersedes the
  -- previous session) invalidates every challenge in flight, for free.
  CONSTRAINT fk_challenge_session
    FOREIGN KEY (session_id, user_id)
    REFERENCES admin.session (id, user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX uq_challenge_value ON webauthn.challenge (challenge);
CREATE INDEX ix_challenge_user_live
  ON webauthn.challenge (user_id) WHERE consumed_at IS NULL;
CREATE INDEX ix_challenge_session ON webauthn.challenge (session_id);

COMMENT ON TABLE webauthn.challenge IS
  'A single-use presence challenge, bound to the heavy action it gates. Consumed atomically: UPDATE ... SET consumed_at = now() WHERE challenge = $1 AND consumed_at IS NULL AND now() < expires_at — zero rows updated means unknown, already consumed, or expired, and the caller refuses. NEVER SELECT-then-UPDATE. Proof gates the TRIGGERING of the action; composing it beforehand needs no challenge. The only NON append-only table here: a spent challenge is worthless, and is purged lazily.';
COMMENT ON COLUMN webauthn.challenge.action IS
  'The action this presence authorizes (e.g. tenant:create). Binds the touch to a specific intent, so a challenge for one action cannot authorize another.';

-- ----------------------------------------------------- admin.retention
-- Same shape as auth.retention, and the same reason: the window is data.
--
--   UPDATE admin.retention SET keep_for = interval '1 day'
--    WHERE relation = 'webauthn.challenge';
--
-- Only ONE relation appears here, and that is the point. token_pair, key,
-- session and user are append-only by trigger AND by the absence of a DELETE
-- grant: they are the audit record, and an audit record you can shorten is not
-- one. At two or three admins on one-hour sessions their growth is measured in
-- rows per day. Challenges are the exception — operational scaffolding,
-- worthless the moment they are spent.
CREATE TABLE admin.retention (
  relation    text        PRIMARY KEY,
  keep_for    interval    NOT NULL,
  batch_size  integer     NOT NULL DEFAULT 5000,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT retention_keep_for_positive
    CHECK (keep_for > interval '0'),
  CONSTRAINT retention_batch_bounded
    CHECK (batch_size BETWEEN 1 AND 100000)
);

COMMENT ON TABLE admin.retention IS
  'How long each purgeable relation is kept. A relation with no row here is not purgeable, which in this schema is nearly all of them: the control plane is an audit record. The policy itself is append-only — you change a window, you never delete the row, because a deleted row silently disables the purge.';

INSERT INTO admin.retention (relation, keep_for) VALUES
  ('webauthn.challenge', interval '7 days');

-- ---------------------------------------------------------------------
-- 5. Signing keys — ONE live signing key per admin, rotated at login
-- ---------------------------------------------------------------------
CREATE TABLE akeys.key (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kid              admin.uuid_v4 NOT NULL,
  user_id          uuid NOT NULL REFERENCES admin."user"(id) ON DELETE RESTRICT,
  session_id       uuid NOT NULL,
  state            akeys.key_state NOT NULL DEFAULT 'PENDING',
  public_jwk       jsonb NOT NULL,
  kms_ref          text NOT NULL,           -- reference to the private key in the KMS; never the key itself
  created_at       timestamptz NOT NULL DEFAULT now(),
  activated_at     timestamptz,
  signs_until      timestamptz NOT NULL,    -- = session.absolute_expires_at (login + 1 h)
  published_until  timestamptz NOT NULL,    -- = signs_until + 10 min grace
  private_destroyed_at timestamptz,         -- KMS material destroyed (orthogonal to expiry)
  CONSTRAINT fk_key_session
    FOREIGN KEY (session_id, user_id)
    REFERENCES admin.session (id, user_id) ON DELETE RESTRICT,
  CONSTRAINT key_activation_coherent
    CHECK ((state = 'ACTIVE') = (activated_at IS NOT NULL)),
  -- BACKSTOPS, unreachable in normal operation: key_bounds_guard runs BEFORE
  -- INSERT and derives signs_until from the session while bumping
  -- published_until, so a caller cannot present values these would reject.
  -- Kept deliberately — they are what still holds if the trigger is ever
  -- dropped or reordered — but do not expect a test to be able to trip them.
  -- Systematic mutation testing reports them as removable for this reason.
  CONSTRAINT key_published_after_signs
    CHECK (published_until > signs_until),
  CONSTRAINT key_signs_after_creation
    CHECK (signs_until > created_at)
);

CREATE UNIQUE INDEX uq_key_kid ON akeys.key (kid);

-- THE core invariant: at most ONE key that may still SIGN, per admin.
-- "may sign" = ACTIVE and now() < signs_until. Because now() is not
-- immutable, this cannot be a pure partial index on a time comparison;
-- the "one ACTIVE signing key per admin" part IS enforceable as an index
-- (a key stops being eligible to sign once a newer one is activated and
-- this one is retired), and the time bound is enforced in the trigger +
-- the resolver. We enforce: at most one ACTIVE, non-retired key per admin.
CREATE UNIQUE INDEX uq_key_one_active_per_admin
  ON akeys.key (user_id)
  WHERE state = 'ACTIVE' AND private_destroyed_at IS NULL;

CREATE INDEX ix_key_user ON akeys.key (user_id);
CREATE INDEX ix_key_session ON akeys.key (session_id);
-- Published (verifiable) keys, for the JWKS endpoint and verifiers.
CREATE INDEX ix_key_published ON akeys.key (published_until)
  WHERE state = 'ACTIVE';

COMMENT ON TABLE akeys.key IS
  'Per-admin signing key, rotated at login, lives one session (1 h) plus a 10 min verification grace. SIGNING and VERIFICATION are distinct: a key signs until signs_until, and stays VERIFIABLE until published_until (covers a command signed at minute 59 reaching a service at minute 61). kid -> user_id makes every signed command carry its author.';
COMMENT ON COLUMN akeys.key.signs_until IS
  '= the session absolute ceiling (login + 1 h). The key may sign only before this instant. Enforced at signing time, not by a partial index (now() is not immutable).';
COMMENT ON COLUMN akeys.key.published_until IS
  '= signs_until + 10 min. A verifier accepts the key until this instant, so an in-flight command signed just before rotation stays verifiable. Never used to sign past signs_until.';
COMMENT ON COLUMN akeys.key.private_destroyed_at IS
  'KMS material destroyed. Orthogonal to expiry: a key past published_until still exists as a public fact for audit; its PRIVATE side is destroyed at rotation so it can never sign again — the same gesture as auth key destruction and crypto-shredding.';

-- ---------------------------------------------------------------------
-- 6. Views — derived states
-- ---------------------------------------------------------------------
CREATE VIEW admin.active_user AS
  SELECT id, created_at, deactivated_at
    FROM admin."user"
   WHERE deactivated_at IS NULL;

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
  WHERE p.replaced_at IS NULL
    AND now() < p.inactivity_expires_at;
COMMENT ON VIEW admin.live_pair IS
  'A pair is refreshable only if not replaced, within its 15 min inactivity window, AND its session is within the 1 h ceiling. Both bounds, derived from now().';

-- Explicit column lists, never SELECT *: kms_ref must never be published by a
-- view simply because it happens to be a column of the table underneath.
CREATE VIEW akeys.signing_key
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, session_id, state, public_jwk,
         created_at, activated_at, signs_until, published_until
  FROM akeys.key
  WHERE state = 'ACTIVE'
    AND private_destroyed_at IS NULL
    AND now() < signs_until;
COMMENT ON VIEW akeys.signing_key IS
  'WHICH key an admin may currently sign with. At most one row per admin. Carries no kms_ref: observing rotation is not the same right as signing.';

CREATE VIEW akeys.signing_material
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, kms_ref, signs_until
  FROM akeys.key
  WHERE state = 'ACTIVE'
    AND private_destroyed_at IS NULL
    AND now() < signs_until;
COMMENT ON VIEW akeys.signing_material IS
  'HOW to sign. The single readable path to kms_ref — SELECT on that column is revoked at table level. Same predicate as signing_key: the KMS reference of a destroyed or expired key is unreachable, so a compromised connection cannot walk the key history looking for material that outlived its window.';

CREATE VIEW akeys.destroyable_key
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, kms_ref, signs_until
  FROM akeys.key
  WHERE private_destroyed_at IS NULL
    AND now() >= signs_until;
COMMENT ON VIEW akeys.destroyable_key IS
  'Keys whose signing window has closed but whose KMS material still exists. The rotation path reads this, destroys each reference, then posts private_destroyed_at. Together with signing_material, kms_ref is readable exactly twice in a key''s life — while it signs, and while it is being destroyed — and never in between or after.';

CREATE VIEW akeys.verifiable_key
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, public_jwk, signs_until, published_until
  FROM akeys.key
  WHERE state = 'ACTIVE'
    AND now() < published_until;
COMMENT ON VIEW akeys.verifiable_key IS
  'Keys a service may currently verify against (published set, incl. the 10 min grace). This is what the JWKS endpoint exposes, so it carries public material only. user_id is present because verification must resolve kid -> admin for attribution; that makes this view internal-facing (sovereign services over gRPC), not something to hang off a public URL — it would publish the admin roster.';

-- ---------------------------------------------------------------------
-- 7. Triggers
-- ---------------------------------------------------------------------

-- 7a. Mono-session: a new session supersedes the previous live one.
--     BEFORE INSERT, not AFTER: the previous session must already be ended
--     when the new row hits uq_session_mono, otherwise every second login
--     would collide with its own predecessor.
-- SECURITY DEFINER, like the guards: this trigger WRITES to a table the
-- caller cannot name. Superseding is the schema's business, not the
-- caller's, and it must not require handing out UPDATE on session.
CREATE FUNCTION admin.session_supersede() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  UPDATE admin.session
     SET ended_at = now(), end_reason = 'SUPERSEDED'
   WHERE user_id = NEW.user_id
     AND ended_at IS NULL
     AND id <> NEW.id;
  RETURN NEW;
END $$;

CREATE TRIGGER session_supersede
  BEFORE INSERT ON admin.session
  FOR EACH ROW EXECUTE FUNCTION admin.session_supersede();

COMMENT ON FUNCTION admin.session_supersede() IS
  'Mono-session for the control plane: a new login ends the previous session (SUPERSEDED) before its own row is inserted. This is the ergonomics — the guarantee is uq_session_mono, which also holds under concurrency (a trigger cannot see uncommitted rows).';

-- 7b. Session emission guard: only an active admin gets a session.
-- SECURITY DEFINER: a guard enforces an invariant on behalf of the SCHEMA,
-- not on behalf of whoever is writing. As an INVOKER function its own
-- lookups run with the caller's rights, so privatising the tables would
-- make every guard demand read access it exists precisely to avoid granting.
CREATE FUNCTION admin.session_emission_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  PERFORM 1 FROM admin.active_user u WHERE u.id = NEW.user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'session refused: admin % is inactive or unknown', NEW.user_id
      USING ERRCODE = 'AD001';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER session_emission_guard
  BEFORE INSERT ON admin.session
  FOR EACH ROW EXECUTE FUNCTION admin.session_emission_guard();

-- 7b-bis. A pair may only be EMITTED on a live session (not ended, within
--         its absolute ceiling). Pendant of auth's pair_emission_guard.
-- SECURITY DEFINER: a guard enforces an invariant on behalf of the SCHEMA,
-- not on behalf of whoever is writing. As an INVOKER function its own
-- lookups run with the caller's rights, so privatising the tables would
-- make every guard demand read access it exists precisely to avoid granting.
CREATE FUNCTION admin.pair_emission_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_ended  timestamptz;
  v_ceil   timestamptz;
  v_user   uuid;
BEGIN
  -- A pair whose two jtis are the same is not a pair: the bearer would be
  -- its own refresh token, and consuming one would consume the other.
  IF NEW.jti_bearer = NEW.jti_refresh THEN
    RAISE EXCEPTION 'token_pair: jti_bearer and jti_refresh must differ'
      USING ERRCODE = 'AD002';
  END IF;

  SELECT ended_at, absolute_expires_at, user_id INTO v_ended, v_ceil, v_user
  FROM admin.session WHERE id = NEW.session_id;

  -- A missing session leaves every variable NULL, and NULL comparisons are not
  -- true: without this the checks below all fall through and the emission is
  -- refused for "the admin is deactivated" (AD003), naming the wrong cause.
  -- The FK would catch it eventually, but only after a misleading error.
  IF NOT FOUND THEN
    RAISE EXCEPTION 'token_pair: session % does not exist', NEW.session_id
      USING ERRCODE = 'AD012';
  END IF;

  IF v_ended IS NOT NULL THEN
    RAISE EXCEPTION 'token_pair: session % is already ended — no pair may be emitted', NEW.session_id
      USING ERRCODE = 'AD012';
  END IF;
  IF now() >= v_ceil THEN
    RAISE EXCEPTION 'token_pair: session % has reached its absolute ceiling — no pair may be emitted', NEW.session_id
      USING ERRCODE = 'AD010';
  END IF;

  -- The admin must STILL be an admin. Checked at every emission, not merely at
  -- login: a session opened an hour ago says nothing about a revocation
  -- decided since. This is what makes rotation frequency equal revocation
  -- latency — rotate on every call and a deactivated admin is stopped on the
  -- very next one, rather than surviving to the absolute ceiling.
  PERFORM 1 FROM admin.active_user u WHERE u.id = v_user;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'token_pair: admin % has been deactivated — no pair may be emitted', v_user
      USING ERRCODE = 'AD003';
  END IF;
  -- A pair must not outlive the session ceiling either.
  IF NEW.inactivity_expires_at > v_ceil THEN
    RAISE EXCEPTION 'token_pair: inactivity window exceeds the session absolute ceiling'
      USING ERRCODE = 'AD013';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER pair_emission_guard
  BEFORE INSERT ON admin.token_pair
  FOR EACH ROW EXECUTE FUNCTION admin.pair_emission_guard();

-- 7b-ter. identity: provider_id is immutable once bound, and bound_at is
--         derived from that binding rather than trusted from the caller.
CREATE FUNCTION admin.identity_bind_once() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD.provider_id IS NOT NULL
       AND NEW.provider_id IS DISTINCT FROM OLD.provider_id THEN
      RAISE EXCEPTION 'identity: provider_id is immutable once bound — rebinding the Entra account of an admin is a bug or an attack'
        USING ERRCODE = 'AD050';
    END IF;
    IF OLD.provider_id IS NULL AND NEW.provider_id IS NOT NULL THEN
      NEW.bound_at := now();
    END IF;
  ELSE
    IF NEW.provider_id IS NOT NULL THEN
      NEW.bound_at := now();
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER identity_bind_once
  BEFORE INSERT OR UPDATE ON admin.identity
  FOR EACH ROW EXECUTE FUNCTION admin.identity_bind_once();

COMMENT ON FUNCTION admin.identity_bind_once() IS
  'The admin plane binds an Entra account ONCE. Every signed command is attributed through kid -> user_id -> identity, so a mutable provider_id would let anyone holding the write path inherit another admin''s signature history retroactively (AD050).';

-- 7c. Key guard: post facts once; forbid a second live signing key.
CREATE FUNCTION akeys.key_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD.private_destroyed_at IS NOT NULL
       AND NEW.private_destroyed_at IS DISTINCT FROM OLD.private_destroyed_at THEN
      RAISE EXCEPTION 'akeys.key: private_destroyed_at is a dated fact, posted once'
        USING ERRCODE = 'AD021';
    END IF;
    IF OLD.state = 'ACTIVE' AND NEW.state = 'PENDING' THEN
      RAISE EXCEPTION 'akeys.key: a key cannot revert to PENDING'
        USING ERRCODE = 'AD021';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER key_guard
  BEFORE UPDATE ON akeys.key
  FOR EACH ROW EXECUTE FUNCTION akeys.key_guard();

-- A key must never be able to sign longer than its session lives.
-- SECURITY DEFINER: a guard enforces an invariant on behalf of the SCHEMA,
-- not on behalf of whoever is writing. As an INVOKER function its own
-- lookups run with the caller's rights, so privatising the tables would
-- make every guard demand read access it exists precisely to avoid granting.
CREATE FUNCTION akeys.key_bounds_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_ceiling timestamptz;
BEGIN
  SELECT absolute_expires_at INTO v_ceiling
  FROM admin.session WHERE id = NEW.session_id;

  -- BEFORE-INSERT triggers run ahead of FK checks, so an unknown session_id
  -- would silently leave v_ceiling NULL and surface as a confusing NOT NULL
  -- violation. Refuse it here and let the FK speak for itself.
  IF v_ceiling IS NULL THEN
    RAISE EXCEPTION 'akeys.key: session % does not exist', NEW.session_id
      USING ERRCODE = 'AD022';
  END IF;

  -- A key must never outlive the session that authorised it. Asking for more
  -- is a caller bug, and silently clamping it would hide the bug while the
  -- registry claims AD022 exists — so it is raised, not repaired.
  IF NEW.signs_until > v_ceiling THEN
    RAISE EXCEPTION 'akeys.key: signs_until (%) exceeds the session absolute ceiling (%)',
      NEW.signs_until, v_ceiling USING ERRCODE = 'AD022';
  END IF;

  -- Below the ceiling, signs_until IS the ceiling: a key lives exactly as long
  -- as its session, and we avoid the "computed a few ms apart" class of bug.
  NEW.signs_until := v_ceiling;
  -- published_until keeps its 10 min grace on top of the authoritative ceiling.
  IF NEW.published_until <= NEW.signs_until THEN
    NEW.published_until := NEW.signs_until + interval '10 minutes';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER key_bounds_guard
  BEFORE INSERT OR UPDATE ON akeys.key
  FOR EACH ROW EXECUTE FUNCTION akeys.key_bounds_guard();

COMMENT ON FUNCTION akeys.key_guard() IS
  'Append-only discipline on keys: destruction is posted once, activation is irreversible. The "one active signing key per admin" bound is held by uq_key_one_active_per_admin.';

-- 7d. Append-only: no DELETE anywhere that carries audit meaning.
CREATE FUNCTION admin.no_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: post a dated fact instead of deleting',
    TG_TABLE_NAME USING ERRCODE = 'AD040';
END $$;

CREATE TRIGGER no_delete_user      BEFORE DELETE ON admin."user"        FOR EACH ROW EXECUTE FUNCTION admin.no_delete();
CREATE TRIGGER no_delete_identity  BEFORE DELETE ON admin.identity      FOR EACH ROW EXECUTE FUNCTION admin.no_delete();
CREATE TRIGGER no_delete_session   BEFORE DELETE ON admin.session       FOR EACH ROW EXECUTE FUNCTION admin.no_delete();
CREATE TRIGGER no_delete_pair      BEFORE DELETE ON admin.token_pair    FOR EACH ROW EXECUTE FUNCTION admin.no_delete();
CREATE TRIGGER no_delete_key       BEFORE DELETE ON akeys.key           FOR EACH ROW EXECUTE FUNCTION admin.no_delete();
CREATE TRIGGER no_delete_authn     BEFORE DELETE ON webauthn.authenticator FOR EACH ROW EXECUTE FUNCTION admin.no_delete();
-- The retention policy itself is append-only: you change a window, you never
-- delete the row. A deleted policy row does not loosen the purge, it silently
-- switches it off — the quietest possible way to break a retention guarantee.
CREATE TRIGGER no_delete_retention BEFORE DELETE ON admin.retention        FOR EACH ROW EXECUTE FUNCTION admin.no_delete();

-- webauthn.challenge is deliberately ABSENT from this list. It is the one
-- table here that carries no audit meaning: a challenge is ephemeral
-- operational scaffolding, worthless once consumed or expired. It is the
-- only table with a DELETE grant, so the lazy purge has somewhere to run.

-- 7e. WebAuthn sign_count must not regress (anti-clone).
CREATE FUNCTION webauthn.sign_count_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  -- STRICTLY greater, as documented. A repeat is as much a clone signal as a
  -- regression: a genuine authenticator increments on every assertion, so an
  -- unchanged counter means the assertion did not come from it.
  IF NEW.sign_count <= OLD.sign_count THEN
    RAISE EXCEPTION 'webauthn: sign_count did not strictly increase (% -> %) — possible cloned authenticator',
      OLD.sign_count, NEW.sign_count USING ERRCODE = 'AD031';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER sign_count_guard
  BEFORE UPDATE OF sign_count ON webauthn.authenticator
  FOR EACH ROW EXECUTE FUNCTION webauthn.sign_count_guard();

-- ---------------------------------------------------------------------
-- 8. Atomic refresh — consume the live pair, enforce BOTH bounds.
--    Returns the consumed pair, or zero rows (replay / expired).
-- ---------------------------------------------------------------------
-- SECURITY DEFINER with an empty search_path, here and on every other function
-- that writes: section 9 revokes the underlying column privileges, so these
-- are the ONLY way to consume a refresh or a challenge. "Never SELECT-then-
-- UPDATE" stops being a comment the author has to have read and becomes 42501.
-- The empty search_path matters: a definer function resolving an unqualified
-- name through the caller's search_path is how you donate the owner's rights.
CREATE FUNCTION admin.consume_pair(p_jti_refresh admin.uuid_v4)
RETURNS TABLE (session_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  UPDATE admin.token_pair p
     SET replaced_at = now()
    FROM admin.session s
   WHERE p.jti_refresh = p_jti_refresh
     AND p.replaced_at IS NULL
     AND s.id = p.session_id
     AND s.ended_at IS NULL
     AND now() < p.inactivity_expires_at
     AND now() < s.absolute_expires_at
  RETURNING p.session_id;
$$;

COMMENT ON FUNCTION admin.consume_pair IS
  'Atomic single-consumption of a refresh. Zero rows returned means: replay (already replaced), inactivity exceeded, or absolute ceiling reached. The caller treats zero rows on an existing pair as a replay -> revoke session (SECURITY). Both time bounds are checked in the same statement.';

-- Rotation in ONE statement: consume the live pair and emit its successor.
-- With rotation on every call this runs constantly, so the window between
-- "consumed" and "re-emitted" must not exist at all — a caller doing it in two
-- statements would leave a session with no live pair every time it crashed in
-- between. The new pair's INSERT fires pair_emission_guard, so every rotation
-- re-checks that the session is live AND the admin still active (AD003):
-- rotate on every call, and revocation latency becomes one call.
CREATE FUNCTION admin.rotate_pair(
  p_jti_refresh admin.uuid_v4,
  p_new_bearer  admin.uuid_v4,
  p_new_refresh admin.uuid_v4,
  p_inactivity  interval DEFAULT interval '15 minutes'
)
RETURNS TABLE (session_id uuid, jti_bearer uuid, jti_refresh uuid,
               inactivity_expires_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  WITH consumed AS (
    UPDATE admin.token_pair p
       SET replaced_at = now()
      FROM admin.session s
     WHERE p.jti_refresh = p_jti_refresh
       AND p.replaced_at IS NULL
       AND s.id = p.session_id
       AND s.ended_at IS NULL
       AND now() < p.inactivity_expires_at
       AND now() < s.absolute_expires_at
    RETURNING p.session_id, s.absolute_expires_at
  )
  INSERT INTO admin.token_pair AS tp
         (session_id, jti_bearer, jti_refresh, inactivity_expires_at)
  SELECT c.session_id, p_new_bearer, p_new_refresh,
         -- clamped, so a rotation can never mint a pair outliving its session
         LEAST(now() + p_inactivity, c.absolute_expires_at)
  FROM consumed c
  RETURNING tp.session_id, tp.jti_bearer, tp.jti_refresh, tp.inactivity_expires_at;
$$;

COMMENT ON FUNCTION admin.rotate_pair IS
  'Atomic refresh rotation: consume + re-emit, one statement. Zero rows means the refresh was not consumable — replay, inactivity exceeded, or session ceiling reached — and the caller treats zero rows on an existing jti as a REPLAY (revoke the session, SECURITY). A deactivated admin does NOT get zero rows: it raises AD003, because that is a different fact and deserves a different reaction.';

-- Presence verification, in ONE statement. Consuming the challenge and
-- advancing the authenticator's counter are not two operations that happen to
-- run together: either both hold or neither does. Split across two statements,
-- an assertion could burn a challenge while skipping the anti-clone check.
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
       -- The session must still be LIVE, not merely be the same row. Binding
       -- the challenge to a session id is not enough on its own: a superseded
       -- or expired session would still match itself, and a proof of presence
       -- collected before a re-login would survive into the session after it.
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

COMMENT ON FUNCTION webauthn.verify_presence IS
  'THE presence gate for a heavy action. Four things must agree in one statement: the challenge exists and is unspent, it was minted for THIS action, it was minted for THIS session, and the authenticator answering belongs to the same admin and is not revoked. Zero rows = refuse, without a SELECT that would be the race. The challenge is burnt even when the authenticator does not match — a failed assertion must not leave a challenge to grind against. A sign_count that fails to advance raises AD031 instead, aborting the statement: a suspected clone is a louder fact than a refusal, and the caller should revoke rather than retry.';

-- Lazy purge of spent challenges. Called on the login path, bounded, and
-- returning its count so a caller wanting a full sweep loops until it is 0.
CREATE FUNCTION webauthn.purge_challenges()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_keep    interval;
  v_batch   integer;
  v_deleted integer;
BEGIN
  SELECT keep_for, batch_size INTO v_keep, v_batch
    FROM admin.retention WHERE relation = 'webauthn.challenge';

  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  WITH doomed AS (
    SELECT c.id
      FROM webauthn.challenge c
     WHERE c.created_at < now() - v_keep
       -- Spent or expired only. A live challenge is a heavy action mid-flight;
       -- age alone must never be enough to cancel someone's pending approval.
       AND (c.consumed_at IS NOT NULL OR c.expires_at < now())
     LIMIT v_batch
  )
  DELETE FROM webauthn.challenge c USING doomed d WHERE c.id = d.id;

  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END $$;

COMMENT ON FUNCTION webauthn.purge_challenges IS
  'Deletes at most batch_size challenges older than admin.retention.keep_for that are already consumed or expired, and returns how many. A challenge still live is never a candidate, whatever its age: it gates an action someone is in the middle of approving. Returns 0 when there is no policy row rather than inventing a default.';

-- The read path. Deliberately NOT a rotation: heavy actions are serialised by
-- the hardware touch that gates them, but reads are not — a dashboard opening
-- three endpoints at once would have three rotations racing, two of them
-- losing, and a loser is indistinguishable from a replay. So the bearer is
-- validated instead of rotated. The control plane serves 2-3 admins, so paying
-- one round trip per call to gain immediate revocation is free here, in a way
-- it would never be in auth: this is exactly where statelessness is worth
-- trading away.
-- SECURITY DEFINER like every other entry point, and for a reason that only
-- appears once the base tables are private: an INVOKER function reads with the
-- CALLER's privileges, so the moment the contract moved to `api` this one
-- started failing with 42501 on tables the plane can no longer name. A curated
-- read is part of the contract exactly as much as a curated write.
CREATE FUNCTION admin.validate_bearer(p_jti_bearer admin.uuid_v4)
RETURNS TABLE (session_id uuid, user_id uuid, valid_until timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT p.session_id, s.user_id,
         LEAST(p.inactivity_expires_at, s.absolute_expires_at)
  FROM admin.token_pair p
  JOIN admin.session s ON s.id = p.session_id
  JOIN admin.active_user u ON u.id = s.user_id
  WHERE p.jti_bearer = p_jti_bearer
    AND p.replaced_at IS NULL
    AND s.ended_at IS NULL
    AND now() < p.inactivity_expires_at
    AND now() < s.absolute_expires_at;
$$;

COMMENT ON FUNCTION admin.validate_bearer IS
  'Called on EVERY request. Zero rows means the bearer is not usable right now — pair rotated away, session ended or past its ceiling, or the admin deactivated since login. That last case is the point: revocation takes effect on the next call, not at the next rotation, and being a pure SELECT it costs nothing under concurrent reads. A cryptographically valid JWT is necessary here, never sufficient.';

-- ---------------------------------------------------------------------
-- 8bis. THE CONTRACT — see the same block in auth.
--
--   Schema `api` is the whole surface the control plane may touch; the base
--   tables are private and, without USAGE on their schemas, unnameable. What
--   the plane cannot name it cannot come to depend on, which is what leaves
--   the storage free to be reshaped over the life of the schema.
--
--   kms_ref appears in exactly one view here, as everywhere else.
-- ---------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS api;
COMMENT ON SCHEMA api IS
  'The only surface the control plane may touch. Tables are private, so they can be reshaped without a coordinated deploy.';

CREATE VIEW api."user" AS
  SELECT id, created_at, deactivated_at FROM admin."user";
CREATE VIEW api.identity
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, provider, provider_id, provision_key, created_at, bound_at
    FROM admin.identity;
CREATE VIEW api.session
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, created_at, absolute_expires_at, ended_at, end_reason
    FROM admin.session;
CREATE VIEW api.token_pair
    WITH (security_invoker = TRUE)
AS
  SELECT id, session_id, jti_bearer, jti_refresh, issued_at,
         inactivity_expires_at, replaced_at
    FROM admin.token_pair;
CREATE VIEW api.authenticator
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, credential_id, public_key, sign_count, label,
         created_at, revoked_at
    FROM webauthn.authenticator;
CREATE VIEW api.challenge
    WITH (security_invoker = TRUE)
AS
  SELECT id, user_id, session_id, challenge, action, created_at, expires_at,
         consumed_at
    FROM webauthn.challenge;
-- kms_ref is present but granted for INSERT only: minting a key writes the
-- reference, reading it back is a separate right served by signing_material.
CREATE VIEW api.key
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, session_id, state, public_jwk, kms_ref, created_at,
         activated_at, signs_until, published_until, private_destroyed_at
    FROM akeys.key;
CREATE VIEW api.retention AS
  SELECT relation, keep_for, batch_size, updated_at FROM admin.retention;

CREATE VIEW api.active_user AS
  SELECT id, created_at, deactivated_at
    FROM admin.active_user;
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
CREATE VIEW api.signing_key
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, session_id, state, public_jwk, created_at, activated_at,
         signs_until, published_until
    FROM akeys.signing_key;
CREATE VIEW api.signing_material
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, kms_ref, signs_until
    FROM akeys.signing_material;
CREATE VIEW api.destroyable_key
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, kms_ref, signs_until
    FROM akeys.destroyable_key;
CREATE VIEW api.verifiable_key
    WITH (security_invoker = TRUE)
AS
  SELECT id, kid, user_id, public_jwk, signs_until, published_until
    FROM akeys.verifiable_key;

-- ---------------------------------------------------------------------
-- 9. Roles & privileges
-- ---------------------------------------------------------------------
-- app_admin_plane, NOT app_admin: Postgres roles are CLUSTER-global, and the
-- `auth` database already owns an app_admin meaning "provisioning of auth".
-- Two databases sharing one role name would silently merge two grant maps and
-- make either migration's rollback destroy the other's privileges.
DO $$
BEGIN
  -- Rôle de PRIVILÈGE (group role, NOLOGIN) : porte les GRANT, jamais utilisé
  -- pour se connecter.
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_admin_plane') THEN
    CREATE ROLE app_admin_plane NOLOGIN;
  END IF;

  -- Rôle de CONNEXION du service admin, pendant de auth_app côté auth.
  -- N'est PAS propriétaire des schémas : le service ne peut donc ni
  -- DROP/TRUNCATE/ALTER, ni écrire hors des colonnes explicitement grantées —
  -- c'est ce qui rend la carte de privilèges réellement active plutôt que
  -- simplement documentée. Sans lui, app_admin_plane ne serait endossable par
  -- personne et la carte ne s'appliquerait qu'en théorie.
  -- Mot de passe de DÉVELOPPEMENT : en production, ALTER ROLE admin_app
  -- PASSWORD depuis le gestionnaire de secrets.
  -- NO PASSWORD HERE. A migration is versioned, committed, and replayed on
  -- every environment: a credential written into one is a credential in the
  -- repository, and the default nobody remembers to change. The role is
  -- created able to log in but unable to authenticate, which fails CLOSED —
  -- in production the password comes from the secrets manager (OpenBao), and
  -- in the sandbox it is set out of band — the Go port has no equivalent of
  -- the previous `npm run credentials` yet.
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin_app') THEN
    CREATE ROLE admin_app LOGIN;
  END IF;
END $$;

-- USAGE on api and on the function schemas only. The base tables are not
-- merely unreadable, they are unnameable.
GRANT USAGE ON SCHEMA api TO app_admin_plane;
GRANT USAGE ON SCHEMA admin, webauthn TO app_admin_plane;   -- functions only

GRANT SELECT ON api."user", api.identity, api.session, api.token_pair
  TO app_admin_plane;
GRANT SELECT ON api.authenticator, api.challenge, api.retention
  TO app_admin_plane;
GRANT SELECT (id, kid, user_id, session_id, state, public_jwk, created_at,
              activated_at, signs_until, published_until, private_destroyed_at)
  ON api.key TO app_admin_plane;
GRANT SELECT ON api.active_user, api.live_session, api.live_pair,
                api.signing_key, api.signing_material,
                api.destroyable_key, api.verifiable_key TO app_admin_plane;

GRANT INSERT ON api.session, api.token_pair TO app_admin_plane;
GRANT INSERT ON api.authenticator, api.challenge TO app_admin_plane;
GRANT INSERT ON api.identity TO app_admin_plane;
GRANT INSERT (kid, user_id, session_id, state, activated_at, public_jwk,
              kms_ref, signs_until, published_until) ON api.key TO app_admin_plane;

GRANT UPDATE (ended_at, end_reason) ON api.session TO app_admin_plane;
-- token_pair gets NO update grant at all: replaced_at moves only through
-- consume_pair / rotate_pair, which do it atomically.
-- bound_at is deliberately absent: the trigger derives it from the binding.
GRANT UPDATE (provider_id, provision_key) ON api.identity TO app_admin_plane;
GRANT UPDATE (deactivated_at) ON api."user" TO app_admin_plane;
-- revoked_at only: an admin may retire a lost key by hand, but sign_count
-- advances solely through verify_presence, coupled to the challenge it proves.
-- Granting sign_count here would allow the counter to be moved without an
-- assertion — which is exactly the anti-clone check being written off.
GRANT UPDATE (revoked_at) ON api.authenticator TO app_admin_plane;
-- consumed_at likewise moves only through verify_presence.
GRANT UPDATE (state, activated_at, private_destroyed_at) ON api.key
  TO app_admin_plane;
-- A function is granted to PUBLIC by default. On a SECURITY DEFINER function
-- that would hand the owner's rights to every role in the cluster, so the
-- default is revoked before anything is granted deliberately.
REVOKE EXECUTE ON FUNCTION
  admin.consume_pair, admin.rotate_pair, webauthn.verify_presence,
  webauthn.purge_challenges FROM PUBLIC;
GRANT EXECUTE ON FUNCTION webauthn.purge_challenges TO app_admin_plane;
-- The plane applies the policy; it does not get to shorten it.
-- validate_bearer is SECURITY INVOKER, so a PUBLIC grant would give away
-- nothing the caller does not already have. Revoked anyway: a reader auditing
-- pg_proc.proacl should not have to work out which functions are exceptions.
REVOKE EXECUTE ON FUNCTION admin.validate_bearer FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin.consume_pair TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.rotate_pair TO app_admin_plane;
GRANT EXECUTE ON FUNCTION admin.validate_bearer TO app_admin_plane;
GRANT EXECUTE ON FUNCTION webauthn.verify_presence TO app_admin_plane;

-- The single DELETE granted in this database, on the single table that is not
-- append-only. Everywhere else, DELETE is refused by BOTH the missing grant
-- (42501) and the no_delete trigger (AD040) — belt and braces, because a
-- superuser-owned connection would bypass the first but never the second.
GRANT DELETE ON api.challenge TO app_admin_plane;

-- Le service se connecte en admin_app, qui HÉRITE de app_admin_plane. Tout ce
-- qui n'est pas granté ci-dessus est refusé (42501) AVANT que le moindre
-- trigger ne s'exécute : moindre privilège appliqué par le moteur, pas
-- seulement affirmé dans le code. La création d'un admin reste hors de portée
-- (aucun INSERT sur admin."user") — un admin est déclaré hors-bande.
-- SEULEMENT SI PERSONNE NE L'A DÉJÀ POSÉE, et ce n'est pas de la prudence
-- décorative : c'est le coeur de la panne la plus coûteuse de ce dépôt.
--
-- Une appartenance de rôle n'est pas un objet. Elle n'a pas de propriétaire,
-- donc `REASSIGN OWNED` ne la transfère pas, et le `DROP OWNED BY <bail>` qui
-- révoque un compte de migration l'EMPORTE avec lui. Posée ici, elle serait
-- donnée par le compte jetable — donc reprise à la révocation suivante, sans
-- bruit. Constaté : admin_app membre de rien, aucun droit, et le service ne s'en
-- apercevait pas parce qu'il se connecte par les comptes dynamiques d'OpenBao.
--
-- `db-init` la pose donc en superutilisateur, par un donneur permanent. Ce bloc
-- ne sert plus qu'aux clusters où personne ne l'a fait — et c'est le cas du banc
-- d'essai, qui rejoue exprès la scène complète pour revoir la panne si elle
-- revient.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT FROM pg_auth_members m
      JOIN pg_roles g ON g.oid = m.roleid
      JOIN pg_roles u ON u.oid = m.member
     WHERE g.rolname = 'app_admin_plane' AND u.rolname = 'admin_app'
  ) THEN
    GRANT app_admin_plane TO admin_app;
  END IF;
END $$;

-- ---------------------------------------------------------------------
-- BLAST RADIUS — see the same block in auth. Tighter here: the control plane
-- serves two or three people and every one of its queries is small, so a
-- second is already generous. A privileged plane that hangs is worse than one
-- that refuses: refusing fails closed, hanging holds locks.
-- ---------------------------------------------------------------------
ALTER ROLE admin_app SET statement_timeout = '2s';
ALTER ROLE admin_app SET lock_timeout = '1s';
ALTER ROLE admin_app SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE admin_app CONNECTION LIMIT 20;

COMMENT ON ROLE admin_app IS
  'Login role of the control plane. Timeouts are deliberately tighter than auth''s: two or three admins, small queries, and failing closed is the correct behaviour for a privileged plane.';

-- Down Migration

-- Schemas carry their tables, views, types, domains, functions and triggers.
DROP SCHEMA IF EXISTS api      CASCADE;
DROP SCHEMA IF EXISTS akeys    CASCADE;
DROP SCHEMA IF EXISTS webauthn CASCADE;
DROP SCHEMA IF EXISTS admin    CASCADE;

-- citext deliberately left in place: it lives in public, it is cheap, and
-- anything else in this database may already depend on it.

-- Roles are CLUSTER-global. DROP OWNED BY sheds only THIS database's grants;
-- DROP ROLE is attempted but tolerated to fail, should anything else in the
-- cluster still reference the role.
-- admin_app first: it is a MEMBER of app_admin_plane, so the group role
-- cannot be dropped while it still exists.
DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['admin_app', 'app_admin_plane'] LOOP
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('DROP OWNED BY %I', r);
      BEGIN
        EXECUTE format('DROP ROLE %I', r);
      EXCEPTION WHEN dependent_objects_still_exist
                  OR dependent_privilege_descriptors_still_exist THEN
        RAISE NOTICE 'role % kept: still referenced elsewhere in this cluster', r;
      END;
    END IF;
  END LOOP;
END $$;
