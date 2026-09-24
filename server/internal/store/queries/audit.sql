-- SPDX-License-Identifier: Apache-2.0

-- LockAuditChain serializes appends to one chain for the current transaction.
-- name: LockAuditChain :exec
SELECT pg_advisory_xact_lock(hashtextextended('kiln.audit:' || sqlc.arg(chain_key)::text, 0));

-- name: GetAuditChainHead :one
SELECT seq, hash FROM audit_events
WHERE chain_key = $1
ORDER BY seq DESC
LIMIT 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (id, chain_key, seq, org_id, occurred_at, actor_kind, actor_id, action,
    target_type, target_id, result, request_id, source_ip, user_agent, details, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17);

-- name: ListAuditEvents :many
SELECT id, chain_key, seq, org_id, occurred_at, actor_kind, actor_id, action, target_type, target_id,
    result, request_id, source_ip, user_agent, details, prev_hash, hash
FROM audit_events
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.arg(before_id)::text = '' OR id < sqlc.arg(before_id)::text)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: ListAuditChain :many
SELECT id, chain_key, seq, org_id, occurred_at, actor_kind, actor_id, action, target_type, target_id,
    result, request_id, source_ip, user_agent, details, prev_hash, hash
FROM audit_events
WHERE chain_key = $1
ORDER BY seq;
