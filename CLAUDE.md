# Kiln — Open-Source CI/CD Platform

Kiln is a self-hostable CI/CD platform: CI pipelines (CircleCI-style), GitOps continuous
delivery (ArgoCD-style), and container-based plugins, with web, desktop, and mobile
clients over one API.

**Kiln executes untrusted code and holds deployment credentials for production
clusters. Security is the top engineering priority, above delivery speed.** When
security and convenience conflict, choose security and explain the trade-off.

This file is loaded every session. Keep it accurate. If you are corrected on the same
thing twice, propose an update to this file.

---

## Required reading

Read these before working in the matching areas. They are authoritative; this file
only summarizes them.

| Before you touch... | Read |
|---|---|
| Any code, first change in a session | `docs/engineering/coding-standards.md` |
| `auth`, `secrets`, `webhooks`, `api`, `gitops`, `runner/`, `proto/`, `apps/desktop/src-tauri`, deploy manifests, CI workflows, or any new dependency | `docs/engineering/security-standards.md` |
| A security review | `.claude/agents/security-reviewer.md` (use the subagent) |

---

## Current status

- **Active phase:** Phase 1 — CI core, in progress (see `docs/roadmap.md`). Server,
  web (React + Tailwind CSS) with the runs UI and log viewer, desktop (Tauri), `runner/`,
  and `proto/` exist; `cli/` and `apps/mobile` do not yet.
- **Stable contracts:** none yet. Treat `docs/api/openapi.yaml` and `proto/` as draft.
- **UI:** Tailwind CSS 4 with native-element primitives in `packages/ui` for web and
  desktop; build-time CSS only, no runtime style injection (ADR-0004).
- **Security target:** OWASP ASVS v4 Level 2 for the server and web app.
- Update this section when a phase completes.

---

## Repository map

```
server/          Go control plane
  cmd/kiln-server/          entrypoint, wiring only
  internal/api/             HTTP transport: handlers, middleware, problem responses
  internal/service/         business logic (one package per domain)
  internal/domain/          entities, value objects, domain errors (no I/O)
  internal/auth/            OIDC, sessions, API tokens, RBAC policy engine
  internal/engine/spec/     pipeline YAML parsing + validation
  internal/engine/dag/      execution graph planning
  internal/scheduler/       job queueing, leasing, retries, timeouts
  internal/rpc/             runner gRPC transport (mTLS, method policy)
  internal/gitops/          reconcile loop, diff, sync, health
  internal/secrets/         envelope encryption, backends (local KMS key, Vault)
  internal/webhooks/        VCS ingest (GitHub, GitLab, Bitbucket)
  internal/store/           sqlc queries + generated code (repositories)
  internal/platform/        config, logging, tracing, metrics, http clients
  migrations/               goose SQL migrations
runner/          Go agent; executors in runner/executor/{docker,kubernetes,shell}
cli/             Go CLI
proto/           gRPC definitions for runner <-> server
packages/        api-client (GENERATED), core (shared TS), ui (DOM components)
apps/            web (React), desktop (Tauri 2), mobile (Expo)
deploy/          helm/, compose/
docs/            adr/, specs/, engineering/, api/openapi.yaml, roadmap.md, threat-model.md
e2e/             end-to-end tests
.github/         workflows (CI + security gates), CODEOWNERS, templates
SECURITY.md      vulnerability disclosure policy
```

Dependency direction in the server is strictly
`api → service → domain` and `service → store`. `domain` imports nothing internal.
Handlers never call `store` directly.

---

## Commands

| Task | Command |
|---|---|
| Full dev stack | `make dev` |
| Infra only | `make infra-up` / `make infra-down` |
| Regenerate code (sqlc, protobuf, OpenAPI Go + TS) | `make generate` |
| All tests | `make test` |
| Single Go test | `go test -run TestName -v ./server/internal/engine/dag` |
| Integration tests (testcontainers) | `make test-integration` |
| Lint (golangci-lint, eslint, clippy, hadolint, actionlint) | `make lint` |
| Security scans (gosec, govulncheck, semgrep, gitleaks, osv-scanner, trivy, pnpm audit) | `make security` |
| Coverage report | `make coverage` |
| New migration | `make migration name=add_runs_table` |
| E2E | `make e2e` |
| Web / desktop / mobile dev | `pnpm --filter web dev` · `pnpm --filter desktop tauri dev` · `pnpm --filter mobile start` |

---

## Definition of Done

A task is not done until all of these hold:

1. `make generate && make lint && make test && make security` pass with no new findings.
2. New or changed logic has tests, including negative and authorization tests.
3. Coverage does not drop; security-critical packages (`auth`, `secrets`, `webhooks`,
   `engine/spec`, runner executors) stay at or above 85%.
4. Public Go identifiers have doc comments; API changes are reflected in OpenAPI.
5. Any new dependency is justified in the summary and passes the dependency policy
   in `security-standards.md`.
6. The end-of-task summary lists security-relevant areas touched (or states "none").

---

## Architecture invariants

Do not violate these without an approved ADR.

1. **OpenAPI is the source of truth.** Change `docs/api/openapi.yaml` first, then
   `make generate`, then implement. Request validation middleware enforces the spec.
2. **Runners pull; the server never pushes.** Outbound gRPC over mTLS only.
3. **Every pipeline step runs in a container.** The `shell` executor is opt-in,
   disabled by default, and blocked for fork PRs.
4. **Logs never go into PostgreSQL.** Chunks go to object storage; live tails over
   NATS → Server-Sent Events (ADR-0007). Secrets are masked by the runner before
   any byte leaves it.
5. **State transitions are explicit.** Use the transition functions in
   `server/internal/engine/states.go`; never set status fields directly.
6. **Clients are thin.** No business logic or authorization decisions in web,
   desktop, or mobile. The server is the only enforcement point.
7. **Single-binary mode keeps working.** `kiln-server --embedded` needs only PostgreSQL.
8. **GitOps is isolated.** `internal/gitops` talks to the rest of the server only
   through events and the store.
9. **Deny by default.** Every route, gRPC method, and Tauri command is denied unless
   explicitly allowed. Only `/healthz`, `/readyz`, webhook ingest (signature-
   verified), and the OIDC pre-auth routes `/api/v1/auth/{login,callback,token}`
   (ADR-0003) are unauthenticated. The router enforces these allowlists at startup.

---

## Security non-negotiables

Full rules and rationale are in `docs/engineering/security-standards.md`. These are
the ones that must never be broken:

- No secrets, tokens, passwords, or keys in code, tests, fixtures, logs, error
  messages, URLs, or commit history. Use `internal/platform/config` and test fakes.
- SQL only through sqlc. No string-built SQL, ever.
- No shell string execution on the server. `exec.Command` with argument arrays only,
  and never with user-controlled binaries.
- Every handler authorizes against the **specific resource** (org/project/app), not
  just the role. Each endpoint has a test proving a user from another org gets 404.
- All outbound HTTP from the server uses `platform/httpclient`, which enforces
  timeouts and SSRF protection (blocks private, loopback, link-local, and cloud
  metadata addresses unless an admin allowlists them).
- Parse untrusted YAML only via `engine/spec`'s safe loader (size, depth, alias
  limits). Never `yaml.Unmarshal` untrusted input directly elsewhere.
- File paths from users or repos are resolved with `platform/safepath` and must stay
  inside their root.
- Crypto: standard library and `golang.org/x/crypto` only. `crypto/rand` for all
  tokens. No custom crypto, no MD5/SHA-1 for security purposes.
- Web: no `dangerouslySetInnerHTML`; log output (including ANSI) is rendered through
  the sanitizing log viewer only. Strict CSP, no inline scripts.
- Fork PRs never receive secrets and never run on `trusted` runners by default.
- Containers run as non-root, without `--privileged`, with dropped capabilities.
  Never mount the Docker socket into a job by default.
- Never disable TLS verification, lint rules, or security scanners to make something
  pass. If a finding is a false positive, stop and explain; suppressions need a
  comment with justification and a maintainer's approval.

---

## Coding conventions (summary)

Full standards: `docs/engineering/coding-standards.md`.

**Go:** stdlib-first; constructor injection, no package-level mutable state;
`context.Context` first on anything that blocks; errors wrapped with `%w` and mapped
to domain errors at the service boundary; `log/slog` with `request_id`, `trace_id`,
`org_id`; OpenTelemetry spans on service methods and outbound calls; timeouts on every
outbound call; table-driven tests; generated files (`*_gen.go`, `*.pb.go`,
`store/db/`) are never hand-edited.

**API:** versioned under `/api/v1`; camelCase JSON; errors as RFC 9457
`application/problem+json`; cursor pagination; `Idempotency-Key` on non-idempotent
POSTs that create runs or deployments; `ETag`/`If-Match` for concurrent updates.

**TypeScript:** `strict`, no `any`; all server calls via `@kiln/api-client`;
TanStack Query for server state; shared logic in `packages/core`; WCAG 2.1 AA for web.

**Rust (desktop):** minimal; window, tray, notifications, local runner lifecycle.
Every Tauri command is allow-listed with least-privilege capabilities.

**Every source file** starts with `// SPDX-License-Identifier: Apache-2.0`.

---

## Common workflows

### Adding an API endpoint
1. Add the path, schemas, security scheme, and error responses to OpenAPI.
2. `make generate`.
3. Add store queries if needed, `make generate` again.
4. Service method in `internal/service/<domain>` with business rules and authorization
   via `authz.Check(ctx, principal, action, resource)`.
5. Thin handler in `internal/api` that maps request → service → response/problem.
6. Tests: happy path, validation error, unauthenticated (401), cross-org access (404),
   insufficient role (403), and rate limit where applicable.
7. Audit-log the action if it mutates secrets, RBAC, runners, or GitOps apps.

### Database changes
Backward-compatible migrations only (expand, then contract in a later release). Both
Up and Down. Indexes for new query paths. Row-level scoping by `org_id` in every
query on tenant data.

### Runner protocol changes
Additive only in `proto/`; never renumber or reuse fields. Old runners work with a new
server for one minor version.

### Pipeline spec changes
Spec doc first, then parser, then fixtures (valid + malicious) in `testdata/`, then
`kiln lint`.

### New dependencies
Check license (allowlist in security standards), maintenance status, and known
vulnerabilities before adding. Prefer the standard library. State the justification
in the summary.

### Architectural decisions
Write an ADR in `docs/adr/` before implementing anything that changes an invariant,
adds a service, or alters a trust boundary. Update `docs/threat-model.md` in the same
change when a trust boundary moves.

---

## How to work in this repo

- **Plan before large changes.** More than ~3 files, any invariant, or any
  security-sensitive area → present a plan (files, approach, risks, threat
  considerations) and wait for approval.
- **One vertical slice at a time.** Finish, test, scan, and summarize before moving on.
- **Run the security-reviewer subagent** on any diff touching the areas listed under
  Required reading, and address its findings before declaring done.
- **Stay in scope.** No unrelated refactors or renames; note them in the summary.
- **Ask when ambiguous**, especially for API contracts, pipeline semantics, and
  anything involving auth, secrets, or execution.
- **Never weaken a test** to make a change pass. If a test looks wrong, stop and explain.
- **Summaries:** what changed, how it was tested, scan results, security areas touched,
  anything left undone.
- **Commits:** Conventional Commits, one logical change each, signed (`git commit -S`).
  Never commit generated code without the source change that produced it.

---

## Glossary

- **Pipeline:** YAML definition in a repo (`.kiln/pipeline.yaml`).
- **Run:** one execution of a pipeline for a trigger.
- **Job:** a DAG node; executes on one runner.
- **Step:** a command or plugin invocation inside a job.
- **Runner:** agent that leases and executes jobs.
- **Lease:** time-bound claim on a job, renewed by heartbeat.
- **Application:** GitOps unit mapping a git source to a cluster/namespace.
- **Sync:** applying an Application's desired state. **Drift:** desired ≠ live.
- **Principal:** the authenticated actor (user, API token, runner, or system).
