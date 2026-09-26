-- SPDX-License-Identifier: Apache-2.0

-- name: CreateRunnerRegistrationToken :exec
INSERT INTO runner_registration_tokens (id, org_id, token_hash, labels, trusted, created_by, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- ClaimRunnerRegistrationToken locks an unused, unexpired token by hash.
-- name: ClaimRunnerRegistrationToken :one
SELECT id, org_id, labels, trusted, created_by
FROM runner_registration_tokens
WHERE token_hash = sqlc.arg(token_hash) AND used_at IS NULL AND expires_at > sqlc.arg(now)
FOR UPDATE;

-- name: MarkRunnerRegistrationTokenUsed :execrows
UPDATE runner_registration_tokens
SET used_at = sqlc.arg(now), runner_id = sqlc.arg(runner_id)
WHERE id = sqlc.arg(id) AND used_at IS NULL;

-- name: CountActiveRunnerRegistrationTokens :one
SELECT count(*) FROM runner_registration_tokens
WHERE org_id = $1 AND used_at IS NULL AND expires_at > $2;

-- name: DeleteExpiredRunnerRegistrationTokens :execrows
DELETE FROM runner_registration_tokens
WHERE used_at IS NULL AND expires_at <= $1;

-- name: CreateRunner :exec
INSERT INTO runners (id, org_id, name, labels, trusted, version, cert_serial, cert_renewed_at,
    cert_expires_at, created_by, created_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetRunner :one
SELECT id, org_id, name, labels, trusted, version, cert_serial, prev_cert_serial, cert_renewed_at,
    cert_expires_at, created_by, created_at, last_seen_at, revoked_at
FROM runners
WHERE org_id = $1 AND id = $2;

-- name: LockRunner :one
SELECT id, org_id, name, labels, trusted, version, cert_serial, prev_cert_serial, cert_renewed_at,
    cert_expires_at, created_by, created_at, last_seen_at, revoked_at
FROM runners
WHERE org_id = $1 AND id = $2
FOR UPDATE;

-- name: ListRunners :many
SELECT id, org_id, name, labels, trusted, version, cert_serial, prev_cert_serial, cert_renewed_at,
    cert_expires_at, created_by, created_at, last_seen_at, revoked_at
FROM runners
WHERE org_id = sqlc.arg(org_id) AND id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- RotateRunnerCertificate records a renewal from the current serial.
-- name: RotateRunnerCertificate :execrows
UPDATE runners
SET prev_cert_serial = cert_serial, cert_serial = sqlc.arg(new_serial),
    cert_renewed_at = sqlc.arg(now), cert_expires_at = sqlc.arg(expires_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND cert_serial = sqlc.arg(current_serial)
  AND revoked_at IS NULL;

-- name: RevokeRunner :execrows
UPDATE runners
SET revoked_at = sqlc.arg(now)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND revoked_at IS NULL;

-- TouchRunner records activity at most once a minute per runner.
-- name: TouchRunner :exec
UPDATE runners
SET last_seen_at = sqlc.arg(now)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND (last_seen_at IS NULL OR last_seen_at < sqlc.arg(now)::timestamptz - interval '1 minute');
