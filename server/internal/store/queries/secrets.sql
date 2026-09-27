-- SPDX-License-Identifier: Apache-2.0

-- name: GetActiveSecretDataKey :one
SELECT org_id, version, key_id, wrapped, active, created_at
FROM secret_data_keys
WHERE org_id = $1 AND active;

-- name: GetSecretDataKey :one
SELECT org_id, version, key_id, wrapped, active, created_at
FROM secret_data_keys
WHERE org_id = $1 AND version = $2;

-- InsertFirstSecretDataKey creates an org's first DEK; a concurrent
-- creator loses quietly and both then read the winner's row.
-- name: InsertFirstSecretDataKey :execrows
INSERT INTO secret_data_keys (org_id, version, key_id, wrapped, active, created_at)
VALUES (sqlc.arg(org_id), 1, sqlc.arg(key_id), sqlc.arg(wrapped), true, sqlc.arg(created_at))
ON CONFLICT DO NOTHING;

-- name: CountSecretDataKeysNotWrappedBy :one
SELECT count(*) FROM secret_data_keys
WHERE NOT (key_id = ANY (sqlc.arg(key_ids)::text[]));

-- LockSecretScope serializes secret creation in one scope for the current
-- transaction, so the per-scope limit cannot be raced.
-- name: LockSecretScope :exec
SELECT pg_advisory_xact_lock(hashtextextended('kiln.secrets:' || sqlc.arg(scope_key)::text, 0));

-- name: CountSecretsInScope :one
SELECT count(*) FROM secrets
WHERE org_id = sqlc.arg(org_id) AND project_id IS NOT DISTINCT FROM sqlc.narg(project_id);

-- name: LockSecret :one
SELECT id, org_id, project_id, name, dek_version, value_version, masked, branches, allow_unprotected,
    all_projects, project_ids, created_by, updated_by, created_at, updated_at
FROM secrets
WHERE org_id = sqlc.arg(org_id) AND project_id IS NOT DISTINCT FROM sqlc.narg(project_id) AND name = sqlc.arg(name)
FOR UPDATE;

-- name: InsertSecret :exec
INSERT INTO secrets (id, org_id, project_id, name, dek_version, value_version, ciphertext, masked, branches,
    allow_unprotected, all_projects, project_ids, created_by, updated_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);

-- name: UpdateSecret :execrows
UPDATE secrets
SET dek_version = sqlc.arg(dek_version), value_version = sqlc.arg(value_version), ciphertext = sqlc.arg(ciphertext),
    masked = sqlc.arg(masked), branches = sqlc.arg(branches), allow_unprotected = sqlc.arg(allow_unprotected),
    all_projects = sqlc.arg(all_projects), project_ids = sqlc.arg(project_ids), updated_by = sqlc.arg(updated_by),
    updated_at = sqlc.arg(updated_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND value_version = sqlc.arg(value_version) - 1;

-- name: ListSecrets :many
SELECT id, org_id, project_id, name, dek_version, value_version, masked, branches, allow_unprotected,
    all_projects, project_ids, created_by, updated_by, created_at, updated_at
FROM secrets
WHERE org_id = sqlc.arg(org_id) AND project_id IS NOT DISTINCT FROM sqlc.narg(project_id)
    AND (sqlc.arg(after_id)::text = '' OR id > sqlc.arg(after_id)::text)
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: DeleteSecret :execrows
DELETE FROM secrets
WHERE org_id = sqlc.arg(org_id) AND project_id IS NOT DISTINCT FROM sqlc.narg(project_id) AND name = sqlc.arg(name);

-- name: GetProjectSlugsByID :many
SELECT id, slug FROM projects
WHERE org_id = sqlc.arg(org_id) AND id = ANY (sqlc.arg(ids)::text[]);

-- name: GetProjectIDsBySlug :many
SELECT id, slug FROM projects
WHERE org_id = sqlc.arg(org_id) AND slug = ANY (sqlc.arg(slugs)::text[]);

-- GetSealedSecret returns a secret's ciphertext for decryption at lease
-- time (ADR-0009 §5); never exposed through the API.
-- name: GetSealedSecret :one
SELECT id, org_id, project_id, name, dek_version, value_version, ciphertext, masked, branches, allow_unprotected,
    all_projects, project_ids, created_by, updated_by, created_at, updated_at
FROM secrets
WHERE org_id = sqlc.arg(org_id) AND project_id IS NOT DISTINCT FROM sqlc.narg(project_id) AND name = sqlc.arg(name);
