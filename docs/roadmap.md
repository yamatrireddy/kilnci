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

## Phase 1 — CI core (in progress)

Pipeline spec + safe YAML loader (fuzzed), DAG planning, scheduler with leases,
runner protocol (`proto/`, mTLS, pull-only), Docker executor (hardened defaults),
log streaming via object storage + NATS with runner-side masking, VCS webhooks
(GitHub first), commit statuses, runs UI with the sanitizing log viewer.
Each item crossing a trust boundary (B1, B2, B3, B6) gets an ADR first.

| Slice | Scope | Status |
|---|---|---|
| 0. ADRs | ADR-0005 runner protocol (B2), ADR-0006 Docker sandbox (B3), ADR-0007 log pipeline (amends invariant 4: SSE), ADR-0008 GitHub App (B1, B6); `docs/specs/pipeline.md` | done |
| 1. Engine | `engine/spec` safe loader (limits, malicious fixtures, `FuzzParse`), `engine/dag`, `engine/states.go` transitions | done |
| 2. Runs | Runs and jobs persisted per org; run read, cancel, approve, and lint APIs | done |
| 3. Scheduler | Leases with heartbeats, completion, reaping, per-runner capacity | done |
| 4. Runner protocol | gRPC over mTLS, pull-only; registration tokens, CSR proof of possession, certificate renewal and revocation | done |
| 5. Docker executor + masking | Hardened sandbox defaults, per-job network and volume, clone container; runner-side streaming masker | done |
| 6. Logs | Chunks in object storage (filesystem/S3), metadata in PostgreSQL, live tails over NATS (in-process bus in `--embedded`) → SSE | done |
| 7. Runner agent | `kiln-runner` CLI, identity management, lease loop, log upload, egress-policy acknowledgement | done |
| 8. GitHub | GitHub App, signature-verified webhook ingest and queue, push/PR triggers, fork detection, manual runs, commit-status outbox | done |
| 9. Security review | Runner and log-pipeline review findings closed (see the PR that closed them and `docs/threat-model.md`) | done |
| 10. Runs UI | Runs and jobs pages, sanitizing ANSI log viewer (T-09); live tails over SSE on web, stored log re-read on desktop | done |
| 11. `kiln lint` CLI | `cli/` wrapper over the lint API | not started |

**Exit criteria:** a push to a linked GitHub repository creates a run, jobs execute
on a registered runner in the hardened Docker sandbox, masked logs stream live to
the runs UI, the commit status reflects the result, and `make generate lint test
test-integration security` is green.

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

### Phase 1 follow-ups

- Desktop live log tails: the IPC bridge (`api_request`) buffers whole responses, so the desktop log viewer re-reads the stored log every 5 s while a job runs. Streaming needs a Tauri channel command (security review of `src-tauri`).
- Log viewer: download the full log (the viewer keeps the last 10 000 lines) and virtualized rendering for very long logs; an incremental stored-log read (`?afterSeq=`) so the desktop fallback stops re-downloading whole logs.
- Runner masker vs. viewer (runs UI security review): the viewer drops escapes and control characters, so a secret split by them (`sec\x1b[1mret`) passes the masker but displays joined. Mask an escape-stripped view of the stream too, and reset SGR/escape state (`ESC \`, `ESC[0m`) before the runner's own `==>` notes.
- Confirm with a test that approving a fork run cannot apply to a later push (each run carries one commit SHA; inferred, not yet tested end to end).
