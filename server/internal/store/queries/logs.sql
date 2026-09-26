-- SPDX-License-Identifier: Apache-2.0

-- LockJobLogState serializes appends for one job.
-- name: LockJobLogState :one
SELECT j.log_bytes, j.log_truncated,
    (SELECT count(*) FROM job_log_chunks c WHERE c.job_id = j.id)::integer AS chunks
FROM jobs j
WHERE j.org_id = sqlc.arg(org_id) AND j.id = sqlc.arg(id)
FOR UPDATE OF j;

-- name: GetJobLogChunk :one
SELECT seq, size, sha256, object_key
FROM job_log_chunks
WHERE org_id = $1 AND job_id = $2 AND seq = $3;

-- name: InsertJobLogChunk :exec
INSERT INTO job_log_chunks (org_id, job_id, seq, size, sha256, object_key, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: AddJobLogBytes :exec
UPDATE jobs
SET log_bytes = log_bytes + sqlc.arg(added)::bigint, log_truncated = log_truncated OR sqlc.arg(truncated)::boolean
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListJobLogChunks :many
SELECT seq, size, object_key
FROM job_log_chunks
WHERE org_id = sqlc.arg(org_id) AND job_id = sqlc.arg(job_id) AND seq >= sqlc.arg(from_seq)
ORDER BY seq
LIMIT sqlc.arg(max_rows);

-- GetRunJob finds a job through its run and project, for authorization.
-- name: GetRunJob :one
SELECT j.id, j.org_id, j.run_id, j.name, j.status, j.log_bytes, j.log_truncated
FROM jobs j
JOIN runs r ON r.org_id = j.org_id AND r.id = j.run_id
WHERE j.org_id = sqlc.arg(org_id) AND r.project_id = sqlc.arg(project_id)
  AND j.run_id = sqlc.arg(run_id) AND j.id = sqlc.arg(job_id);
