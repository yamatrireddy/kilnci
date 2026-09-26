-- SPDX-License-Identifier: Apache-2.0

-- name: NextRunNumber :one
INSERT INTO project_run_counters (project_id, org_id, last_number)
VALUES (sqlc.arg(project_id), sqlc.arg(org_id), 1)
ON CONFLICT (project_id) DO UPDATE SET last_number = project_run_counters.last_number + 1
RETURNING last_number;

-- name: CreateRun :one
INSERT INTO runs (id, org_id, project_id, number, status, event, ref, branch, commit_sha, title,
    pr_number, is_fork, trusted, actor_login, created_by, idempotency_key, error, created_at,
    started_at, finished_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
RETURNING id, org_id, project_id, number, status, event, ref, branch, commit_sha, title, pr_number,
    is_fork, trusted, actor_login, created_by, idempotency_key, error, created_at, started_at, finished_at;

-- name: GetRun :one
SELECT id, org_id, project_id, number, status, event, ref, branch, commit_sha, title, pr_number,
    is_fork, trusted, actor_login, created_by, idempotency_key, error, created_at, started_at, finished_at
FROM runs
WHERE org_id = $1 AND project_id = $2 AND id = $3;

-- LockRun locks a run row for the rest of the transaction.
-- name: LockRun :one
SELECT id, org_id, project_id, number, status, event, ref, branch, commit_sha, title, pr_number,
    is_fork, trusted, actor_login, created_by, idempotency_key, error, created_at, started_at, finished_at
FROM runs
WHERE org_id = $1 AND id = $2
FOR UPDATE;

-- name: GetRunByIdempotencyKey :one
SELECT id, org_id, project_id, number, status, event, ref, branch, commit_sha, title, pr_number,
    is_fork, trusted, actor_login, created_by, idempotency_key, error, created_at, started_at, finished_at
FROM runs
WHERE org_id = $1 AND project_id = $2 AND idempotency_key = $3;

-- name: ListRuns :many
SELECT id, org_id, project_id, number, status, event, ref, branch, commit_sha, title, pr_number,
    is_fork, trusted, actor_login, created_by, idempotency_key, error, created_at, started_at, finished_at
FROM runs
WHERE org_id = sqlc.arg(org_id) AND project_id = sqlc.arg(project_id)
  AND (sqlc.arg(before_id)::text = '' OR id < sqlc.arg(before_id)::text)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- UpdateRunStatus is a compare-and-swap: it changes nothing unless the run
-- is still in from_status. Timestamps are set once and never cleared.
-- name: UpdateRunStatus :execrows
UPDATE runs
SET status = sqlc.arg(to_status),
    started_at = COALESCE(started_at, sqlc.narg(started_at)),
    finished_at = COALESCE(finished_at, sqlc.narg(finished_at))
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = sqlc.arg(from_status);

-- name: CreateJob :exec
INSERT INTO jobs (id, org_id, run_id, name, status, needs, image, labels, steps, env,
    timeout_seconds, attempt, max_attempts, trusted, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);

-- name: ListJobs :many
SELECT id, org_id, run_id, name, status, needs, image, labels, steps, env, timeout_seconds, attempt,
    max_attempts, trusted, runner_id, cancel_requested, exit_code, failure_reason, created_at,
    queued_at, started_at, finished_at
FROM jobs
WHERE org_id = $1 AND run_id = $2
ORDER BY id;

-- UpdateJobStatus is a compare-and-swap on a job that is not leased (queued,
-- pending, or being canceled/failed while queued). Leased jobs are changed
-- only through the scheduler's lease-bound queries.
-- name: UpdateJobStatus :execrows
UPDATE jobs
SET status = sqlc.arg(to_status),
    queued_at = CASE WHEN sqlc.arg(to_status)::text = 'queued' THEN sqlc.narg(at) ELSE queued_at END,
    finished_at = CASE WHEN sqlc.arg(to_status)::text IN ('succeeded', 'failed', 'canceled', 'skipped')
        THEN sqlc.narg(at) ELSE finished_at END,
    failure_reason = CASE WHEN sqlc.arg(failure_reason)::text = '' THEN failure_reason ELSE sqlc.arg(failure_reason)::text END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = sqlc.arg(from_status)
  AND status <> 'running';

-- name: RequestJobCancel :execrows
UPDATE jobs
SET cancel_requested = true
WHERE org_id = $1 AND id = $2 AND status = 'running';
