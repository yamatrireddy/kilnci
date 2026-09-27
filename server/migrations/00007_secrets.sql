-- SPDX-License-Identifier: Apache-2.0
--
-- Phase 2: pipeline secrets (ADR-0009). Values are stored only as
-- AES-256-GCM ciphertext under a per-org data key (DEK); DEKs are stored only
-- wrapped by a key-encryption key that never touches the database.

-- +goose Up

CREATE TABLE secret_data_keys (
    org_id     text NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    version    integer NOT NULL CHECK (version >= 1),
    -- Names the KEK (or Vault key version) that wrapped this DEK.
    key_id     text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 200),
    wrapped    bytea NOT NULL CHECK (length(wrapped) BETWEEN 1 AND 8192),
    active     boolean NOT NULL,
    created_at timestamptz NOT NULL,
    rewrapped_at timestamptz,
    PRIMARY KEY (org_id, version)
);
-- Exactly one DEK per org is used for new writes.
CREATE UNIQUE INDEX secret_data_keys_active ON secret_data_keys (org_id) WHERE active;
-- Startup and rewrap look up DEKs by the KEK that wrapped them.
CREATE INDEX secret_data_keys_key_id ON secret_data_keys (key_id);

CREATE TABLE secrets (
    id                text PRIMARY KEY,
    org_id            text NOT NULL,
    -- NULL for org secrets.
    project_id        text,
    name              text NOT NULL CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'),
    dek_version       integer NOT NULL,
    value_version     bigint NOT NULL CHECK (value_version >= 1),
    -- version byte + nonce + ciphertext + tag, for values up to 64 KiB.
    ciphertext        bytea NOT NULL CHECK (length(ciphertext) BETWEEN 29 AND 65565),
    masked            boolean NOT NULL,
    branches          text[] NOT NULL DEFAULT '{}' CHECK (cardinality(branches) <= 20),
    allow_unprotected boolean NOT NULL DEFAULT false,
    -- Which projects may use an org secret (ADR-0009 §3). Project secrets
    -- leave both empty.
    all_projects      boolean NOT NULL DEFAULT false,
    project_ids       text[] NOT NULL DEFAULT '{}' CHECK (cardinality(project_ids) <= 100),
    created_by        text REFERENCES users (id) ON DELETE SET NULL,
    updated_by        text REFERENCES users (id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    CONSTRAINT secrets_org FOREIGN KEY (org_id) REFERENCES orgs (id) ON DELETE CASCADE,
    CONSTRAINT secrets_project FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id) ON DELETE CASCADE,
    -- A value can only be sealed under a DEK of its own org.
    CONSTRAINT secrets_dek FOREIGN KEY (org_id, dek_version) REFERENCES secret_data_keys (org_id, version),
    CONSTRAINT secrets_project_scope CHECK (project_id IS NULL OR (NOT all_projects AND cardinality(project_ids) = 0))
);
CREATE UNIQUE INDEX secrets_org_name ON secrets (org_id, name) WHERE project_id IS NULL;
CREATE UNIQUE INDEX secrets_project_name ON secrets (org_id, project_id, name) WHERE project_id IS NOT NULL;
-- Cursor pagination per scope.
CREATE INDEX secrets_scope_id ON secrets (org_id, project_id, id);

-- +goose Down

DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS secret_data_keys;
