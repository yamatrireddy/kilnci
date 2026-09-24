-- SPDX-License-Identifier: Apache-2.0

-- name: GetUserByOIDC :one
SELECT id, oidc_issuer, oidc_subject, email, display_name, instance_admin, created_at
FROM users
WHERE oidc_issuer = $1 AND oidc_subject = $2;

-- name: GetUser :one
SELECT id, oidc_issuer, oidc_subject, email, display_name, instance_admin, created_at
FROM users
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT id, oidc_issuer, oidc_subject, email, display_name, instance_admin, created_at
FROM users
WHERE lower(email) = lower(sqlc.arg(email));

-- name: CreatePendingUser :one
INSERT INTO users (id, email, display_name, created_at)
VALUES ($1, $2, $3, $4)
RETURNING id, oidc_issuer, oidc_subject, email, display_name, instance_admin, created_at;

-- ClaimPendingUser binds an IdP identity to an invited (unclaimed) account.
-- name: ClaimPendingUser :one
UPDATE users
SET oidc_issuer = sqlc.arg(issuer), oidc_subject = sqlc.arg(subject),
    display_name = sqlc.arg(display_name),
    instance_admin = instance_admin OR sqlc.arg(grant_instance_admin)::boolean
WHERE lower(email) = lower(sqlc.arg(email)) AND oidc_issuer IS NULL
RETURNING id, oidc_issuer, oidc_subject, email, display_name, instance_admin, created_at;

-- name: CreateUser :one
INSERT INTO users (id, oidc_issuer, oidc_subject, email, display_name, instance_admin, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, oidc_issuer, oidc_subject, email, display_name, instance_admin, created_at;

-- Instance admin can be granted (bootstrap list) but never revoked by sign-in.
-- name: UpdateUserProfile :one
UPDATE users
SET email = sqlc.arg(email),
    display_name = sqlc.arg(display_name),
    instance_admin = instance_admin OR sqlc.arg(grant_instance_admin)::boolean
WHERE id = sqlc.arg(id)
RETURNING id, oidc_issuer, oidc_subject, email, display_name, instance_admin, created_at;
