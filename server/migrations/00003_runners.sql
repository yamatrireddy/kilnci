-- SPDX-License-Identifier: Apache-2.0
--
-- Phase 1: runners and their single-use registration tokens (ADR-0005).
-- Token secrets are never stored, only SHA-256 hashes. Runners are revoked
-- (revoked_at), never hard-deleted while jobs reference them.

-- +goose Up

CREATE TABLE runners (
    id               text PRIMARY KEY,
    org_id           text NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    labels           text[] NOT NULL,
    trusted          boolean NOT NULL,
    version          text NOT NULL DEFAULT '' CHECK (length(version) <= 64),
    -- How many jobs the runner may hold at once.
    capacity         integer NOT NULL DEFAULT 1 CHECK (capacity BETWEEN 1 AND 16),
    -- Current and previous client-certificate serials (hex). Only the
    -- current one may renew; the previous one works for a grace period.
    cert_serial      text NOT NULL,
    -- The current certificate and its key hash let a lost renewal response
    -- be retried idempotently (same key) without being mistaken for reuse.
    cert_der         bytea NOT NULL,
    cert_spki_sha256 bytea NOT NULL,
    prev_cert_serial text,
    cert_renewed_at  timestamptz NOT NULL,
    cert_expires_at  timestamptz NOT NULL,
    created_by       text REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL,
    last_seen_at     timestamptz,
    revoked_at       timestamptz,
    CONSTRAINT runners_org_id_id UNIQUE (org_id, id)
);
CREATE INDEX runners_org ON runners (org_id, id);

CREATE TABLE runner_registration_tokens (
    id         text PRIMARY KEY,
    org_id     text NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL,
    labels     text[] NOT NULL,
    trusted    boolean NOT NULL,
    created_by text REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    runner_id  text,
    CONSTRAINT runner_registration_tokens_hash UNIQUE (token_hash),
    CONSTRAINT runner_registration_tokens_single_use CHECK ((used_at IS NULL) = (runner_id IS NULL))
);

-- A job's runner must belong to the job's org.
ALTER TABLE jobs ADD CONSTRAINT jobs_runner
    FOREIGN KEY (org_id, runner_id) REFERENCES runners (org_id, id) ON DELETE SET NULL (runner_id);

-- +goose Down

ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_runner;
DROP TABLE IF EXISTS runner_registration_tokens;
DROP TABLE IF EXISTS runners;
