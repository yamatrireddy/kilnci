-- SPDX-License-Identifier: Apache-2.0
--
-- Phase 1: job log chunk metadata (ADR-0007). Log content lives in object
-- storage (invariant 4); PostgreSQL only records which chunks exist, their
-- size, and a content hash so replays with different bytes are rejected.

-- +goose Up

ALTER TABLE jobs ADD CONSTRAINT jobs_org_id_id UNIQUE (org_id, id);

CREATE TABLE job_log_chunks (
    org_id     text NOT NULL,
    job_id     text NOT NULL,
    seq        integer NOT NULL CHECK (seq >= 0 AND seq < 16384),
    size       integer NOT NULL CHECK (size BETWEEN 0 AND 262144),
    sha256     bytea NOT NULL CHECK (length(sha256) = 32),
    object_key text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (job_id, seq),
    CONSTRAINT job_log_chunks_job FOREIGN KEY (org_id, job_id) REFERENCES jobs (org_id, id) ON DELETE CASCADE
);

ALTER TABLE jobs ADD COLUMN log_bytes bigint NOT NULL DEFAULT 0 CHECK (log_bytes >= 0);
ALTER TABLE jobs ADD COLUMN log_truncated boolean NOT NULL DEFAULT false;

-- +goose Down

ALTER TABLE jobs DROP COLUMN IF EXISTS log_truncated;
ALTER TABLE jobs DROP COLUMN IF EXISTS log_bytes;
DROP TABLE IF EXISTS job_log_chunks;
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_org_id_id;
