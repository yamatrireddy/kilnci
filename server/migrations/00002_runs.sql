-- SPDX-License-Identifier: Apache-2.0
--
-- Phase 1: runs and jobs. Status columns are only ever changed through
-- compare-and-swap updates driven by internal/engine/states.go. Logs are not
-- stored here (invariant 4). Lease columns are used by internal/scheduler.

-- +goose Up

-- Per-project run numbers, allocated under a row lock.
CREATE TABLE project_run_counters (
    project_id  text PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    org_id      text NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    last_number bigint NOT NULL DEFAULT 0
);

CREATE TABLE runs (
    id              text PRIMARY KEY,
    org_id          text NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    project_id      text NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    number          bigint NOT NULL,
    status          text NOT NULL CHECK (status IN ('awaiting_approval', 'queued', 'running', 'succeeded', 'failed', 'canceled')),
    event           text NOT NULL CHECK (event IN ('push', 'pull_request', 'manual')),
    ref             text NOT NULL CHECK (length(ref) BETWEEN 1 AND 255),
    branch          text NOT NULL CHECK (length(branch) <= 255),
    commit_sha      text NOT NULL CHECK (commit_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    title           text NOT NULL DEFAULT '' CHECK (length(title) <= 1024),
    pr_number       integer NOT NULL DEFAULT 0 CHECK (pr_number >= 0),
    is_fork         boolean NOT NULL,
    trusted         boolean NOT NULL,
    actor_login     text NOT NULL DEFAULT '' CHECK (length(actor_login) <= 255),
    created_by      text REFERENCES users (id) ON DELETE SET NULL,
    idempotency_key text CHECK (length(idempotency_key) BETWEEN 1 AND 255),
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 8192),
    created_at      timestamptz NOT NULL,
    started_at      timestamptz,
    finished_at     timestamptz,
    CONSTRAINT runs_project_number UNIQUE (project_id, number),
    CONSTRAINT runs_project_idempotency UNIQUE (project_id, idempotency_key),
    -- A run from a fork is never trusted (ADR-0005 §9, ADR-0008 §5).
    CONSTRAINT runs_fork_untrusted CHECK (NOT (is_fork AND trusted))
);
-- Newest-first listing per project.
CREATE INDEX runs_project ON runs (org_id, project_id, id DESC);

CREATE TABLE jobs (
    id               text PRIMARY KEY,
    org_id           text NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    run_id           text NOT NULL REFERENCES runs (id) ON DELETE CASCADE,
    name             text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_-]{0,62}$'),
    status           text NOT NULL CHECK (status IN ('pending', 'queued', 'running', 'succeeded', 'failed', 'canceled', 'skipped')),
    needs            text[] NOT NULL,
    image            text NOT NULL CHECK (length(image) BETWEEN 1 AND 255),
    labels           text[] NOT NULL,
    steps            jsonb NOT NULL,
    env              jsonb NOT NULL,
    timeout_seconds  integer NOT NULL CHECK (timeout_seconds BETWEEN 60 AND 86400),
    attempt          integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempts     integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 4),
    trusted          boolean NOT NULL,
    runner_id        text,
    lease_id         bytea,
    lease_expires_at timestamptz,
    cancel_requested boolean NOT NULL DEFAULT false,
    exit_code        integer,
    failure_reason   text NOT NULL DEFAULT '' CHECK (length(failure_reason) <= 1024),
    created_at       timestamptz NOT NULL,
    queued_at        timestamptz,
    started_at       timestamptz,
    finished_at      timestamptz,
    CONSTRAINT jobs_run_name UNIQUE (run_id, name),
    -- A leased job always has a runner and an expiry; nothing else has a lease.
    CONSTRAINT jobs_lease_consistent CHECK (
        (status = 'running') = (lease_id IS NOT NULL AND lease_expires_at IS NOT NULL AND runner_id IS NOT NULL)
    )
);
CREATE INDEX jobs_run ON jobs (run_id);
-- Scheduler: the queue per org, and expired-lease reaping.
CREATE INDEX jobs_queue ON jobs (org_id, queued_at) WHERE status = 'queued';
CREATE INDEX jobs_lease_expiry ON jobs (lease_expires_at) WHERE status = 'running';

-- +goose Down

DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS project_run_counters;
