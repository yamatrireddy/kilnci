-- SPDX-License-Identifier: Apache-2.0

-- name: CreateAPIToken :one
INSERT INTO api_tokens (id, user_id, name, prefix, token_hash, scopes, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, user_id, name, prefix, scopes, created_at, expires_at, last_used_at, revoked_at;

-- name: GetAPITokenByHash :one
SELECT id, user_id, name, prefix, scopes, created_at, expires_at, last_used_at, revoked_at
FROM api_tokens WHERE token_hash = $1;

-- name: ListAPITokens :many
SELECT id, user_id, name, prefix, scopes, created_at, expires_at, last_used_at, revoked_at
FROM api_tokens
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY id;

-- name: CountActiveAPITokens :one
SELECT count(*) FROM api_tokens
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2;

-- name: RevokeAPIToken :execrows
UPDATE api_tokens SET revoked_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND revoked_at IS NULL;

-- Coalesces last-used writes to at most one per minute per token.
-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = sqlc.arg(now)
WHERE id = sqlc.arg(id)
  AND (last_used_at IS NULL OR last_used_at < sqlc.arg(now) - interval '1 minute');
