-- SPDX-License-Identifier: Apache-2.0
--
-- Phase 1: scope job log chunks to a lease attempt (ADR-0007 §1). A job
-- whose lease lapsed is re-queued as the same row, so chunks keyed only by
-- (job_id, seq) made a retry collide with the first attempt's output. Each
-- chunk now records the attempt, runner, and lease that wrote it (ADR-0007,
-- Repudiation), and the job's log byte count restarts with each attempt.

-- +goose Up

ALTER TABLE job_log_chunks ADD COLUMN attempt integer NOT NULL DEFAULT 1 CHECK (attempt >= 1);
ALTER TABLE job_log_chunks ADD COLUMN runner_id text;
ALTER TABLE job_log_chunks ADD COLUMN lease_id bytea;
ALTER TABLE job_log_chunks ADD COLUMN sha256_request bytea CHECK (sha256_request IS NULL OR length(sha256_request) = 32);

-- Existing chunks belong to the job's latest attempt as far as anyone can tell.
UPDATE job_log_chunks c SET attempt = greatest(j.attempt, 1)
FROM jobs j WHERE j.org_id = c.org_id AND j.id = c.job_id;

ALTER TABLE job_log_chunks DROP CONSTRAINT job_log_chunks_pkey;
ALTER TABLE job_log_chunks ADD PRIMARY KEY (job_id, attempt, seq);

-- +goose Down

-- Only the latest attempt's chunks fit the old key; earlier attempts' rows
-- are dropped (their objects are left in object storage).
DELETE FROM job_log_chunks c USING jobs j
WHERE j.org_id = c.org_id AND j.id = c.job_id AND c.attempt <> greatest(j.attempt, 1);
ALTER TABLE job_log_chunks DROP CONSTRAINT job_log_chunks_pkey;
ALTER TABLE job_log_chunks ADD PRIMARY KEY (job_id, seq);
ALTER TABLE job_log_chunks DROP COLUMN IF EXISTS sha256_request;
ALTER TABLE job_log_chunks DROP COLUMN IF EXISTS lease_id;
ALTER TABLE job_log_chunks DROP COLUMN IF EXISTS runner_id;
ALTER TABLE job_log_chunks DROP COLUMN IF EXISTS attempt;
