<!-- SPDX-License-Identifier: Apache-2.0 -->
# Kiln Roadmap

Phases are sequential. Each phase ends when its exit criteria hold and the
Definition of Done in `CLAUDE.md` passes. Threat-model entries move from **P** to
**I**/**V** in `docs/threat-model.md` as their controls ship.

Mobile (Expo) is deferred until after Phase 2; the API it needs is the same one web
and desktop use.

---

## Phase 0 — Foundations (implemented; pending maintainer review)

Goal: a secure, observable skeleton that every later feature plugs into, so no
feature has to invent its own auth, error model, config, or UI conventions.

| Slice | Scope | Status |
|---|---|---|
| 0. Repo layout | Monorepo layout, Makefile, pinned tools, lint/depguard layering, Semgrep rules, CI + security workflows, CODEOWNERS, PR template, ADR process | done |
| 1. Server skeleton | `platform/config`, `platform/logging` (slog + redaction), `domain` errors, RFC 9457 problems, request ID, security headers, body limits, deny-by-default router, `/healthz` `/readyz`, graceful shutdown, `platform/httpclient` (SSRF) | done |
| 2. OpenAPI + codegen | Draft `openapi.yaml` (health, auth, session, orgs, members, projects, audit, tokens), oapi-codegen types, `@kiln/api-client`, request validation middleware, route/spec conformance test | done |
| 3. Persistence | PostgreSQL, goose migrations (embedded, locked), sqlc repositories scoped by `org_id`, `store.InTx`, append-only hash-chained audit table, testcontainers integration tests | done |
| 4. Auth | OIDC (Auth Code + PKCE) for web and desktop (ADR-0003), server-side sessions, CSRF, desktop token rotation, API tokens, RBAC + `authz.Check`, authz matrix test, audit events, rate limits | done |
| 5. Web app | React + Tailwind CSS (ADR-0004, superseding Mantine/ADR-0002) + TanStack Query; sign-in, orgs, projects, members, audit log, API tokens; loading/empty/error states; axe checks; strict CSP verified in a browser | done |
| 6. Desktop shell | Tauri 2 wrapping the shared UI; 5 allow-listed commands; Rust-held tokens (keychain); loopback PKCE sign-in; CSP | done |

**Exit criteria:** a user signs in via OIDC on web or desktop, sees only their orgs
and projects, cross-org access returns 404 in the authz matrix, and `make generate
lint test security` is green.

## Phase 1 — CI core

Pipeline spec + safe YAML loader (fuzzed), DAG planning, scheduler with leases,
runner protocol (`proto/`, mTLS, pull-only), Docker executor (hardened defaults),
log streaming via object storage + NATS with runner-side masking, VCS webhooks
(GitHub first), commit statuses, runs UI with the sanitizing log viewer.
Each item crossing a trust boundary (B1, B2, B3, B6) gets an ADR first.

## Phase 2 — Secrets and trust

Envelope encryption (local key, Vault Transit, KMS), scoped secrets, fork-PR
policies, trusted/untrusted runner pools, cache scoping by trust level,
`platform/httpclient` SSRF suite, hash-chained audit log with SIEM export.

## Phase 3 — GitOps

Applications, reconcile loop, diff/sync/health, sandboxed Helm/Kustomize rendering,
per-app namespace/kind allow-lists, sync approvals.

## Phase 4 — Plugins, Kubernetes executor, mobile

Container plugins with declared capabilities, Kubernetes executor (PSS restricted),
Expo mobile app (read + approvals with biometric confirmation).

## Phase 5 — Hardening for 1.0

SLSA L3 releases (cosign, SBOM, provenance), Helm chart hardened defaults, DAST,
third-party penetration test, stable `/api/v1` contract.

### Phase 0 follow-ups (carried into Phase 1)

- Audit log: separate migration/owner DB role and head anchoring (threat model §9).
- Code-split the web bundle (~700 kB); `--embedded` mode becomes meaningful once NATS/object storage exist.
- Desktop: signed auto-updates with a pinned key (T-37) and the local runner (T-36).
- `make e2e`: compose-based end-to-end suite (webhook → run → logs) once runs exist.
