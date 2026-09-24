-- SPDX-License-Identifier: Apache-2.0

-- name: CreateWebSession :exec
INSERT INTO web_sessions (id, token_hash, user_id, created_at, last_seen_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetWebSessionByHash :one
SELECT id, token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at
FROM web_sessions
WHERE token_hash = $1;

-- name: TouchWebSession :exec
UPDATE web_sessions SET last_seen_at = $2
WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeWebSession :exec
UPDATE web_sessions SET revoked_at = $2
WHERE id = $1 AND revoked_at IS NULL;

-- name: CreateLoginState :exec
INSERT INTO login_states (state_hash, client, nonce, idp_code_verifier, return_to,
    desktop_redirect_uri, desktop_code_challenge, desktop_state, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- TakeLoginState deletes and returns the state so it can be used only once.
-- name: TakeLoginState :one
DELETE FROM login_states
WHERE state_hash = $1
RETURNING state_hash, client, nonce, idp_code_verifier, return_to,
    desktop_redirect_uri, desktop_code_challenge, desktop_state, created_at, expires_at;

-- name: DeleteExpiredLoginStates :execrows
DELETE FROM login_states WHERE expires_at < $1;

-- name: CreateDesktopAuthCode :exec
INSERT INTO desktop_auth_codes (code_hash, user_id, code_challenge, redirect_uri, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- UseDesktopAuthCode marks an unused code as used and returns it; a second
-- redemption finds no row.
-- name: UseDesktopAuthCode :one
UPDATE desktop_auth_codes SET used_at = sqlc.arg(now)
WHERE code_hash = sqlc.arg(code_hash) AND used_at IS NULL
RETURNING code_hash, user_id, code_challenge, redirect_uri, created_at, expires_at, used_at;

-- name: CreateDesktopGrant :exec
INSERT INTO desktop_grants (id, user_id, created_at, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetDesktopGrant :one
SELECT id, user_id, created_at, expires_at, revoked_at
FROM desktop_grants WHERE id = $1;

-- name: RevokeDesktopGrant :exec
UPDATE desktop_grants SET revoked_at = $2
WHERE id = $1 AND revoked_at IS NULL;

-- name: CreateRefreshToken :exec
INSERT INTO desktop_refresh_tokens (token_hash, grant_id, created_at, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetRefreshTokenForUpdate :one
SELECT token_hash, grant_id, created_at, expires_at, used_at
FROM desktop_refresh_tokens WHERE token_hash = $1
FOR UPDATE;

-- name: MarkRefreshTokenUsed :exec
UPDATE desktop_refresh_tokens SET used_at = $2 WHERE token_hash = $1;

-- name: CreateAccessToken :exec
INSERT INTO desktop_access_tokens (token_hash, grant_id, created_at, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetAccessToken :one
SELECT t.token_hash, t.grant_id, t.expires_at, g.user_id,
    g.revoked_at AS grant_revoked_at, g.expires_at AS grant_expires_at
FROM desktop_access_tokens t
JOIN desktop_grants g ON g.id = t.grant_id
WHERE t.token_hash = $1;

-- name: DeleteExpiredAccessTokens :execrows
DELETE FROM desktop_access_tokens WHERE expires_at < $1;

-- Sessions and codes are kept for a day after expiry for incident review.
-- name: DeleteExpiredWebSessions :execrows
DELETE FROM web_sessions WHERE expires_at < sqlc.arg(cutoff);

-- name: DeleteExpiredDesktopAuthCodes :execrows
DELETE FROM desktop_auth_codes WHERE expires_at < sqlc.arg(cutoff);

-- name: DeleteExpiredRefreshTokens :execrows
DELETE FROM desktop_refresh_tokens WHERE expires_at < sqlc.arg(cutoff);

-- Grants cascade to their remaining tokens.
-- name: DeleteExpiredDesktopGrants :execrows
DELETE FROM desktop_grants WHERE expires_at < sqlc.arg(cutoff);
