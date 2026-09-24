-- SPDX-License-Identifier: Apache-2.0

-- name: CreateProject :one
INSERT INTO projects (id, org_id, slug, name, created_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, org_id, slug, name, created_at;

-- name: GetProject :one
SELECT id, org_id, slug, name, created_at
FROM projects
WHERE org_id = $1 AND slug = $2;

-- name: ListProjects :many
SELECT id, org_id, slug, name, created_at
FROM projects
WHERE org_id = sqlc.arg(org_id) AND id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(max_rows);
