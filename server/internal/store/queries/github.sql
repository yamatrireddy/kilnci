-- SPDX-License-Identifier: Apache-2.0

-- name: BindGitHubInstallation :exec
INSERT INTO github_installations (installation_id, org_id, account_login, bound_by, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetGitHubInstallation :one
SELECT installation_id, org_id, account_login, bound_by, created_at, disabled_at
FROM github_installations
WHERE installation_id = $1;

-- name: ListGitHubInstallationsForOrg :many
SELECT installation_id, org_id, account_login, bound_by, created_at, disabled_at
FROM github_installations
WHERE org_id = $1
ORDER BY installation_id;

-- name: DeleteGitHubInstallation :execrows
DELETE FROM github_installations WHERE installation_id = $1;

-- name: DisableGitHubInstallation :exec
UPDATE github_installations SET disabled_at = COALESCE(disabled_at, sqlc.arg(now))
WHERE installation_id = sqlc.arg(installation_id);

-- name: DisableRepositoriesForInstallation :exec
UPDATE repositories SET disabled_at = COALESCE(disabled_at, sqlc.arg(now))
WHERE installation_id = sqlc.arg(installation_id);

-- name: DisableRepositoriesByRepoID :exec
UPDATE repositories SET disabled_at = COALESCE(disabled_at, sqlc.arg(now))
WHERE installation_id = sqlc.arg(installation_id) AND repo_id = ANY(sqlc.arg(repo_ids)::bigint[]);

-- name: LinkRepository :exec
INSERT INTO repositories (id, org_id, project_id, installation_id, repo_id, full_name, clone_url,
    default_branch, private, linked_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetRepositoryForProject :one
SELECT id, org_id, project_id, installation_id, repo_id, full_name, clone_url, default_branch, private,
    linked_by, created_at, disabled_at
FROM repositories
WHERE org_id = $1 AND project_id = $2;

-- GetActiveRepositoryByRepoID finds the enabled link for a GitHub repository
-- whose installation is bound and enabled.
-- name: GetActiveRepositoryByRepoID :one
SELECT r.id, r.org_id, r.project_id, r.installation_id, r.repo_id, r.full_name, r.clone_url,
    r.default_branch, r.private, r.linked_by, r.created_at, r.disabled_at
FROM repositories r
JOIN github_installations i ON i.installation_id = r.installation_id AND i.org_id = r.org_id
WHERE r.repo_id = $1 AND r.disabled_at IS NULL AND i.disabled_at IS NULL;

-- name: UnlinkRepository :execrows
DELETE FROM repositories WHERE org_id = $1 AND project_id = $2;

-- name: InsertWebhookDelivery :execrows
INSERT INTO webhook_deliveries (id, delivery_id, body_sha256, event, payload, received_at, next_attempt_at)
VALUES ($1, $2, $3, $4, $5, $6, $6)
ON CONFLICT DO NOTHING;

-- name: ClaimWebhookDeliveries :many
SELECT id, event, payload, attempts
FROM webhook_deliveries
WHERE status = 'pending' AND next_attempt_at <= sqlc.arg(now)
ORDER BY received_at
LIMIT sqlc.arg(max_rows)
FOR UPDATE SKIP LOCKED;

-- name: FinishWebhookDelivery :exec
UPDATE webhook_deliveries
SET status = sqlc.arg(status), outcome = sqlc.arg(outcome), processed_at = sqlc.arg(now), attempts = attempts + 1
WHERE id = sqlc.arg(id);

-- name: RetryWebhookDelivery :exec
UPDATE webhook_deliveries
SET attempts = attempts + 1, next_attempt_at = sqlc.arg(next_attempt_at), outcome = sqlc.arg(outcome)
WHERE id = sqlc.arg(id);

-- name: DeleteOldWebhookDeliveries :execrows
DELETE FROM webhook_deliveries WHERE received_at < $1;

-- name: InsertCommitStatus :exec
INSERT INTO commit_status_outbox (id, org_id, run_id, repo_id, installation_id, commit_sha, state, context,
    description, target_url, created_at, next_attempt_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11);

-- SupersedeCommitStatuses marks unsent statuses that a newer one for the same
-- commit and context replaces, so an old state never overwrites a new one.
-- name: SupersedeCommitStatuses :exec
UPDATE commit_status_outbox o SET sent_at = sqlc.arg(now)
WHERE o.sent_at IS NULL AND EXISTS (
    SELECT 1 FROM commit_status_outbox n
    WHERE n.repo_id = o.repo_id AND n.commit_sha = o.commit_sha AND n.context = o.context AND n.id > o.id);

-- name: ClaimCommitStatuses :many
SELECT id, installation_id, repo_id, commit_sha, state, context, description, target_url, attempts
FROM commit_status_outbox
WHERE sent_at IS NULL AND next_attempt_at <= sqlc.arg(now)
ORDER BY id
LIMIT sqlc.arg(max_rows)
FOR UPDATE SKIP LOCKED;

-- name: MarkCommitStatusSent :exec
UPDATE commit_status_outbox SET sent_at = sqlc.arg(now), attempts = attempts + 1 WHERE id = sqlc.arg(id);

-- name: RetryCommitStatus :exec
UPDATE commit_status_outbox SET attempts = attempts + 1, next_attempt_at = sqlc.arg(next_attempt_at)
WHERE id = sqlc.arg(id);

-- GetRunStatusTarget returns what a commit status for a run needs.
-- name: GetRunStatusTarget :one
SELECT r.repo_id, r.installation_id, p.slug AS project_slug, o.slug AS org_slug
FROM repositories r
JOIN projects p ON p.org_id = r.org_id AND p.id = r.project_id
JOIN orgs o ON o.id = r.org_id
JOIN github_installations i ON i.installation_id = r.installation_id AND i.org_id = r.org_id
WHERE r.org_id = $1 AND r.project_id = $2 AND r.disabled_at IS NULL AND i.disabled_at IS NULL;
