-- SPDX-License-Identifier: Apache-2.0

-- LockJobLogState serializes appends for one job and re-checks the lease
-- under the row lock, so a runner whose lease lapsed (and was re-leased)
-- cannot append between a check and the insert. Log bytes are those of the
-- current attempt.
-- name: LockJobLogState :one
SELECT j.run_id, j.attempt, j.log_bytes, j.log_truncated
FROM jobs j
WHERE j.org_id = sqlc.arg(org_id) AND j.id = sqlc.arg(id) AND j.status = 'running'
  AND j.runner_id = sqlc.arg(runner_id) AND j.lease_id = sqlc.arg(lease_id)
  AND j.lease_expires_at > sqlc.arg(now)
FOR UPDATE OF j;

-- CountJobLogChunks runs after LockJobLogState as its own statement, so it
-- sees chunks committed by an append that held the lock before (a subquery
-- in the locking statement would read the snapshot taken before the wait).
-- name: CountJobLogChunks :one
SELECT count(*)::integer
FROM job_log_chunks
WHERE org_id = $1 AND job_id = $2 AND attempt = $3;

-- name: GetJobLogChunk :one
SELECT seq, size, sha256, sha256_request, object_key
FROM job_log_chunks
WHERE org_id = $1 AND job_id = $2 AND attempt = $3 AND seq = $4;

-- name: InsertJobLogChunk :exec
INSERT INTO job_log_chunks (org_id, job_id, attempt, seq, size, sha256, sha256_request, object_key, runner_id, lease_id, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: AddJobLogBytes :exec
UPDATE jobs
SET log_bytes = log_bytes + sqlc.arg(added)::bigint, log_truncated = log_truncated OR sqlc.arg(truncated)::boolean
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListJobLogChunks :many
SELECT seq, size, object_key
FROM job_log_chunks
WHERE org_id = sqlc.arg(org_id) AND job_id = sqlc.arg(job_id) AND attempt = sqlc.arg(attempt)
  AND seq >= sqlc.arg(from_seq)
ORDER BY seq
LIMIT sqlc.arg(max_rows);

-- GetRunJob finds a job through its run and project, for authorization.
-- name: GetRunJob :one
SELECT j.id, j.org_id, j.run_id, j.name, j.status, j.attempt, j.log_bytes, j.log_truncated
FROM jobs j
JOIN runs r ON r.org_id = j.org_id AND r.id = j.run_id
WHERE j.org_id = sqlc.arg(org_id) AND r.project_id = sqlc.arg(project_id)
  AND j.run_id = sqlc.arg(run_id) AND j.id = sqlc.arg(job_id);
