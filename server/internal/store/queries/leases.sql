-- SPDX-License-Identifier: Apache-2.0
--
-- Job leases (ADR-0005 §7). Lock order is always run row, then job row:
-- callers find a candidate without locking, lock its run, then apply a
-- compare-and-swap on the job. Every lease-bound change requires the lease
-- ID, the leasing runner, and an unexpired lease.

-- name: ListLeaseCandidates :many
SELECT id, run_id
FROM jobs
WHERE org_id = sqlc.arg(org_id)
  AND status = 'queued'
  AND labels <@ sqlc.arg(runner_labels)::text[]
  -- A trusted runner never takes an untrusted job (fork PRs, ADR-0005 §9).
  AND (trusted OR NOT sqlc.arg(runner_trusted)::boolean)
ORDER BY queued_at, id
LIMIT sqlc.arg(max_rows);

-- AcquireLease re-checks the runner against its current row at grant time:
-- it must not be revoked, must still have the job's labels and trust, and
-- must be below its capacity (a long-polling Lease call must not outlive a
-- revocation).
-- name: AcquireLease :execrows
UPDATE jobs
SET status = 'running',
    runner_id = sqlc.arg(runner_id),
    lease_id = sqlc.arg(lease_id),
    lease_expires_at = sqlc.arg(lease_expires_at),
    attempt = attempt + 1,
    started_at = sqlc.arg(now),
    cancel_requested = false
WHERE jobs.org_id = sqlc.arg(org_id) AND jobs.id = sqlc.arg(id) AND jobs.status = 'queued'
  AND EXISTS (
      SELECT 1 FROM runners r
      WHERE r.org_id = jobs.org_id AND r.id = sqlc.arg(runner_id) AND r.revoked_at IS NULL
        AND jobs.labels <@ r.labels
        AND (jobs.trusted OR NOT r.trusted)
        AND (SELECT count(*) FROM jobs held
             WHERE held.org_id = r.org_id AND held.runner_id = r.id AND held.status = 'running') < r.capacity
  );

-- ReleaseLease puts a job that was leased but never delivered back in the
-- queue without spending an attempt.
-- name: ReleaseLease :execrows
UPDATE jobs
SET status = 'queued', lease_id = NULL, lease_expires_at = NULL, runner_id = NULL,
    attempt = attempt - 1, started_at = NULL, queued_at = sqlc.arg(now)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = 'running'
  AND runner_id = sqlc.arg(runner_id) AND lease_id = sqlc.arg(lease_id) AND attempt > 0;

-- name: GetLeasedJob :one
SELECT id, org_id, run_id, name, status, needs, image, labels, steps, env, timeout_seconds, attempt,
    max_attempts, trusted, runner_id, cancel_requested, exit_code, failure_reason, created_at,
    queued_at, started_at, finished_at, lease_expires_at
FROM jobs
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = 'running'
  AND runner_id = sqlc.arg(runner_id) AND lease_id = sqlc.arg(lease_id)
  AND lease_expires_at > sqlc.arg(now);

-- name: RenewLease :one
UPDATE jobs
SET lease_expires_at = sqlc.arg(lease_expires_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = 'running'
  AND runner_id = sqlc.arg(runner_id) AND lease_id = sqlc.arg(lease_id)
  AND lease_expires_at > sqlc.arg(now)
RETURNING cancel_requested, started_at, timeout_seconds;

-- name: CompleteLeasedJob :execrows
UPDATE jobs
SET status = sqlc.arg(to_status),
    lease_id = NULL,
    lease_expires_at = NULL,
    exit_code = sqlc.narg(exit_code),
    failure_reason = sqlc.arg(failure_reason),
    finished_at = sqlc.arg(now)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = 'running'
  AND runner_id = sqlc.arg(runner_id) AND lease_id = sqlc.arg(lease_id)
  AND lease_expires_at > sqlc.arg(now);

-- ListExpiredLeases finds running jobs whose lease lapsed or whose hard
-- timeout (plus grace) passed, across all orgs, for the reaper.
-- name: ListExpiredLeases :many
SELECT id, org_id, run_id
FROM jobs
WHERE status = 'running'
  AND (lease_expires_at <= sqlc.arg(now)
       OR started_at + make_interval(secs => timeout_seconds + sqlc.arg(grace_seconds)::integer) <= sqlc.arg(now))
ORDER BY lease_expires_at
LIMIT sqlc.arg(max_rows);

-- RequeueExpiredJob gives a job whose lease lapsed another attempt.
-- name: RequeueExpiredJob :execrows
UPDATE jobs
SET status = 'queued', lease_id = NULL, lease_expires_at = NULL, runner_id = NULL,
    queued_at = sqlc.arg(now), started_at = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = 'running'
  AND lease_expires_at <= sqlc.arg(now) AND attempt < max_attempts AND NOT cancel_requested
  AND started_at + make_interval(secs => timeout_seconds) > sqlc.arg(now);

-- FailExpiredJob ends a job whose lease lapsed with no attempts left, that
-- was being canceled, or that exceeded its timeout.
-- name: FailExpiredJob :execrows
UPDATE jobs
SET status = sqlc.arg(to_status), lease_id = NULL, lease_expires_at = NULL,
    failure_reason = sqlc.arg(failure_reason), finished_at = sqlc.arg(now)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = 'running'
  AND (lease_expires_at <= sqlc.arg(now)
       OR started_at + make_interval(secs => timeout_seconds + sqlc.arg(grace_seconds)::integer) <= sqlc.arg(now));

-- LockRunnerForLease serializes lease grants per runner so the capacity
-- check in AcquireLease cannot be raced. Lock order: run, runner, job.
-- name: LockRunnerForLease :one
SELECT id FROM runners
WHERE org_id = $1 AND id = $2
FOR NO KEY UPDATE;
