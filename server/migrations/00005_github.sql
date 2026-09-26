-- SPDX-License-Identifier: Apache-2.0
--
-- Phase 1: GitHub App installations bound to orgs, repositories linked to
-- projects, the webhook delivery queue, and the commit-status outbox
-- (ADR-0008). Links use GitHub's immutable numeric IDs, never names.

-- +goose Up

ALTER TABLE runs ADD CONSTRAINT runs_org_id_id UNIQUE (org_id, id);

-- An instance admin binds each installation to exactly one Kiln org.
CREATE TABLE github_installations (
    installation_id bigint PRIMARY KEY CHECK (installation_id > 0),
    org_id          text NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    account_login   text NOT NULL DEFAULT '' CHECK (length(account_login) <= 255),
    bound_by        text REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL,
    disabled_at     timestamptz,
    CONSTRAINT github_installations_org UNIQUE (org_id, installation_id)
);

-- At most one project per repository on the instance, and one repository
-- per project.
CREATE TABLE repositories (
    id              text PRIMARY KEY,
    org_id          text NOT NULL,
    project_id      text NOT NULL,
    installation_id bigint NOT NULL,
    repo_id         bigint NOT NULL CHECK (repo_id > 0),
    full_name       text NOT NULL CHECK (length(full_name) BETWEEN 3 AND 255),
    clone_url       text NOT NULL CHECK (clone_url LIKE 'https://%'),
    default_branch  text NOT NULL CHECK (length(default_branch) BETWEEN 1 AND 255),
    private         boolean NOT NULL,
    linked_by       text REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL,
    disabled_at     timestamptz,
    CONSTRAINT repositories_project UNIQUE (project_id),
    CONSTRAINT repositories_repo UNIQUE (repo_id),
    CONSTRAINT repositories_project_fk FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id) ON DELETE CASCADE,
    -- The installation must be bound to the same org as the project.
    CONSTRAINT repositories_installation_fk FOREIGN KEY (org_id, installation_id)
        REFERENCES github_installations (org_id, installation_id) ON DELETE CASCADE
);

-- Verified webhook deliveries awaiting processing. Deduplicated by the
-- delivery ID and by the body hash (GitHub signs only the body).
CREATE TABLE webhook_deliveries (
    id              text PRIMARY KEY,
    delivery_id     text NOT NULL CHECK (length(delivery_id) BETWEEN 1 AND 100),
    body_sha256     bytea NOT NULL CHECK (length(body_sha256) = 32),
    event           text NOT NULL CHECK (event IN ('push', 'pull_request', 'installation', 'installation_repositories', 'ping')),
    payload         bytea NOT NULL CHECK (length(payload) <= 5242880),
    received_at     timestamptz NOT NULL,
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'failed')),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    processed_at    timestamptz,
    outcome         text NOT NULL DEFAULT '' CHECK (length(outcome) <= 255),
    CONSTRAINT webhook_deliveries_delivery UNIQUE (delivery_id),
    CONSTRAINT webhook_deliveries_body UNIQUE (body_sha256)
);
CREATE INDEX webhook_deliveries_pending ON webhook_deliveries (next_attempt_at) WHERE status = 'pending';
CREATE INDEX webhook_deliveries_received ON webhook_deliveries (received_at);

-- Commit statuses to post to GitHub, written in the same transaction as the
-- run state change that caused them.
CREATE TABLE commit_status_outbox (
    id              text PRIMARY KEY,
    org_id          text NOT NULL,
    run_id          text NOT NULL,
    repo_id         bigint NOT NULL,
    installation_id bigint NOT NULL,
    commit_sha      text NOT NULL CHECK (commit_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    state           text NOT NULL CHECK (state IN ('pending', 'success', 'failure', 'error')),
    context         text NOT NULL CHECK (length(context) BETWEEN 1 AND 255),
    description     text NOT NULL CHECK (length(description) <= 140),
    target_url      text NOT NULL CHECK (target_url LIKE 'https://%' OR target_url LIKE 'http://localhost%'),
    created_at      timestamptz NOT NULL,
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    sent_at         timestamptz,
    CONSTRAINT commit_status_outbox_run FOREIGN KEY (org_id, run_id) REFERENCES runs (org_id, id) ON DELETE CASCADE
);
CREATE INDEX commit_status_outbox_pending ON commit_status_outbox (next_attempt_at) WHERE sent_at IS NULL;

-- +goose Down

DROP TABLE IF EXISTS commit_status_outbox;
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS repositories;
DROP TABLE IF EXISTS github_installations;
ALTER TABLE runs DROP CONSTRAINT IF EXISTS runs_org_id_id;
