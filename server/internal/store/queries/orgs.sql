-- SPDX-License-Identifier: Apache-2.0

-- name: CreateOrg :one
INSERT INTO orgs (id, slug, name, created_at)
VALUES ($1, $2, $3, $4)
RETURNING id, slug, name, created_at;

-- GetOrgForMember is the tenant-scoped org lookup: it returns a row only when
-- the user is a member, so non-members cannot tell "exists" from "not found".
-- name: GetOrgForMember :one
SELECT o.id, o.slug, o.name, o.created_at, m.role
FROM orgs o
JOIN memberships m ON m.org_id = o.id
WHERE o.slug = sqlc.arg(slug) AND m.user_id = sqlc.arg(user_id);

-- name: ListOrgsForMember :many
SELECT o.id, o.slug, o.name, o.created_at, m.role
FROM orgs o
JOIN memberships m ON m.org_id = o.id
WHERE m.user_id = sqlc.arg(user_id) AND o.id > sqlc.arg(after_id)
ORDER BY o.id
LIMIT sqlc.arg(max_rows);

-- name: GetMembershipRole :one
SELECT role FROM memberships
WHERE org_id = $1 AND user_id = $2;

-- name: AddMembership :exec
INSERT INTO memberships (org_id, user_id, role, created_at)
VALUES ($1, $2, $3, $4);

-- name: UpdateMembershipRole :execrows
UPDATE memberships SET role = $3
WHERE org_id = $1 AND user_id = $2;

-- name: DeleteMembership :execrows
DELETE FROM memberships
WHERE org_id = $1 AND user_id = $2;

-- LockOwners locks the org's owner rows so "last owner" checks are race-free.
-- name: LockOwners :many
SELECT user_id FROM memberships
WHERE org_id = $1 AND role = 'owner'
ORDER BY user_id
FOR UPDATE;

-- name: GetMember :one
SELECT m.user_id, u.email, u.display_name, m.role
FROM memberships m
JOIN users u ON u.id = m.user_id
WHERE m.org_id = $1 AND m.user_id = $2;

-- name: ListMembers :many
SELECT m.user_id, u.email, u.display_name, m.role
FROM memberships m
JOIN users u ON u.id = m.user_id
WHERE m.org_id = sqlc.arg(org_id) AND m.user_id > sqlc.arg(after_user_id)
ORDER BY m.user_id
LIMIT sqlc.arg(max_rows);

-- GetOrgBySlug is for instance-admin operations only (no membership check).
-- name: GetOrgBySlug :one
SELECT id, slug, name, created_at FROM orgs WHERE slug = $1;
