-- SPDX-License-Identifier: Apache-2.0
--
-- Phase 0 schema: identities, tenancy, sessions, API tokens, audit log.
-- Conventions: IDs are ULID text; timestamps are timestamptz (UTC); secrets are
-- never stored, only SHA-256 hashes of high-entropy tokens.

-- +goose Up

-- A user with no OIDC identity yet is a pending invite, claimed on first
-- sign-in by the verified email it was invited with (ADR-0003).
CREATE TABLE users (
    id             text PRIMARY KEY,
    oidc_issuer    text,
    oidc_subject   text,
    email          text NOT NULL,
    display_name   text NOT NULL,
    instance_admin boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_oidc_identity UNIQUE (oidc_issuer, oidc_subject),
    CONSTRAINT users_oidc_identity_complete CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL))
);
-- Members are added by email; one Kiln account per email address.
CREATE UNIQUE INDEX users_email_lower ON users (lower(email));

CREATE TABLE orgs (
    id         text PRIMARY KEY,
    slug       text NOT NULL,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT orgs_slug UNIQUE (slug)
);

CREATE TABLE memberships (
    org_id     text NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    user_id    text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('viewer', 'developer', 'admin', 'owner')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
-- "Which orgs is this user in?" (org list, authz lookups).
CREATE INDEX memberships_user ON memberships (user_id, org_id);

CREATE TABLE projects (
    id         text PRIMARY KEY,
    org_id     text NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    slug       text NOT NULL,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT projects_org_slug UNIQUE (org_id, slug)
);
-- Cursor pagination within an org.
CREATE INDEX projects_org_id ON projects (org_id, id);

-- Browser sessions. The cookie carries a 256-bit secret; only its hash is stored.
CREATE TABLE web_sessions (
    id           text PRIMARY KEY,
    token_hash   bytea NOT NULL,
    user_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    CONSTRAINT web_sessions_token_hash UNIQUE (token_hash)
);
CREATE INDEX web_sessions_user ON web_sessions (user_id);

-- In-flight OIDC logins, keyed by the hash of the state parameter.
CREATE TABLE login_states (
    state_hash             bytea PRIMARY KEY,
    client                 text NOT NULL CHECK (client IN ('web', 'desktop')),
    nonce                  text NOT NULL,
    idp_code_verifier      text NOT NULL,
    return_to              text NOT NULL DEFAULT '',
    desktop_redirect_uri   text NOT NULL DEFAULT '',
    desktop_code_challenge text NOT NULL DEFAULT '',
    desktop_state          text NOT NULL DEFAULT '',
    created_at             timestamptz NOT NULL,
    expires_at             timestamptz NOT NULL
);
CREATE INDEX login_states_expires ON login_states (expires_at);

-- One-time codes handed to the desktop app's loopback redirect (RFC 8252).
CREATE TABLE desktop_auth_codes (
    code_hash      bytea PRIMARY KEY,
    user_id        text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_challenge text NOT NULL,
    redirect_uri   text NOT NULL,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz
);

-- A desktop sign-in ("grant") owns a family of rotating refresh tokens and
-- short-lived access tokens. Revoking the grant revokes them all.
CREATE TABLE desktop_grants (
    id         text PRIMARY KEY,
    user_id    text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX desktop_grants_user ON desktop_grants (user_id);

CREATE TABLE desktop_refresh_tokens (
    token_hash bytea PRIMARY KEY,
    grant_id   text NOT NULL REFERENCES desktop_grants (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX desktop_refresh_tokens_grant ON desktop_refresh_tokens (grant_id);

CREATE TABLE desktop_access_tokens (
    token_hash bytea PRIMARY KEY,
    grant_id   text NOT NULL REFERENCES desktop_grants (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX desktop_access_tokens_grant ON desktop_access_tokens (grant_id);

-- Personal API tokens (kiln_pat_...). Hash only; the secret is shown once.
CREATE TABLE api_tokens (
    id           text PRIMARY KEY,
    user_id      text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text NOT NULL,
    prefix       text NOT NULL,
    token_hash   bytea NOT NULL,
    scopes       text[] NOT NULL,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    CONSTRAINT api_tokens_token_hash UNIQUE (token_hash)
);
CREATE INDEX api_tokens_user ON api_tokens (user_id, id);

-- Append-only, hash-chained audit log (security-standards §12). chain_key is
-- the org ID, or '' for instance-level events. Each row's hash covers its
-- content and the previous row's hash, so edits and deletions are detectable.
CREATE TABLE audit_events (
    id          text PRIMARY KEY,
    chain_key   text NOT NULL,
    seq         bigint NOT NULL,
    org_id      text REFERENCES orgs (id) ON DELETE RESTRICT,
    occurred_at timestamptz NOT NULL,
    actor_kind  text NOT NULL,
    actor_id    text NOT NULL,
    action      text NOT NULL,
    target_type text NOT NULL,
    target_id   text NOT NULL,
    result      text NOT NULL CHECK (result IN ('success', 'denied')),
    request_id  text NOT NULL,
    source_ip   text NOT NULL,
    user_agent  text NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   bytea NOT NULL,
    hash        bytea NOT NULL,
    CONSTRAINT audit_events_chain_seq UNIQUE (chain_key, seq)
);
CREATE INDEX audit_events_org ON audit_events (org_id, id DESC);

-- +goose StatementBegin
CREATE FUNCTION audit_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();

-- +goose Down

DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
DROP TRIGGER IF EXISTS audit_events_no_update_delete ON audit_events;
DROP FUNCTION IF EXISTS audit_events_append_only();
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS desktop_access_tokens;
DROP TABLE IF EXISTS desktop_refresh_tokens;
DROP TABLE IF EXISTS desktop_grants;
DROP TABLE IF EXISTS desktop_auth_codes;
DROP TABLE IF EXISTS login_states;
DROP TABLE IF EXISTS web_sessions;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS orgs;
DROP TABLE IF EXISTS users;
