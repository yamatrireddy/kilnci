# Kiln Coding Standards

These standards apply to all code in the Kiln repository. They exist so that a large,
changing group of contributors produces code that is consistent, reviewable,
observable, and safe to operate in enterprise environments.

"Must" means required and enforced in review or CI. "Should" means expected unless
there is a documented reason.

---

## 1. Architecture and layering (server)

The server uses a layered design with a strict dependency direction:

```
api (transport)  →  service (use cases)  →  domain (entities, rules, errors)
                         ↓
                    store (persistence)      platform (config, logging, http, crypto helpers)
```

- `domain` must not import any other internal package or perform I/O.
- `api` handlers must be thin: decode, call one service method, encode. No business
  rules, no direct `store` access.
- `service` owns business rules, authorization checks, transactions, and audit events.
- `store` exposes repository interfaces defined in `service` (interfaces belong to the
  consumer). Implementations wrap sqlc-generated code.
- Cross-domain calls go through service interfaces, not concrete types.
- `cmd/*` contains wiring only. No logic.

These rules are enforced by `depguard` in `golangci-lint`.

## 2. Naming and structure

- Packages: short, lowercase, singular, no `util`, `common`, `helpers`, or `misc`.
- Files: `snake_case.go`; tests beside the code as `*_test.go`.
- Interfaces: named by behavior (`RunLeaser`, `SecretDecrypter`), not `IFoo`.
- Constructors: `NewX(deps...) (*X, error)` when validation can fail.
- Booleans read as questions: `isTerminal`, `hasApproval`.
- TypeScript components `PascalCase.tsx`; hooks `useThing.ts`; one component per file.
- Abbreviations keep consistent case: `ID`, `URL`, `HTTP` in Go (`runID`, `apiURL`).

## 3. Error model

- Domain errors are typed and declared in `internal/domain/errors.go`:
  `ErrNotFound`, `ErrConflict`, `ErrValidation`, `ErrForbidden`, `ErrUnauthenticated`,
  `ErrRateLimited`, `ErrPreconditionFailed`.
- Lower layers wrap with context: `fmt.Errorf("lease job %s: %w", jobID, err)`.
- Services translate infrastructure errors into domain errors; `sql.ErrNoRows`
  must never leak past `store`.
- The API layer maps domain errors to RFC 9457 problem responses in exactly one place
  (`internal/api/problem.go`). Clients get a stable `type` URI, `title`, `status`,
  and a `requestId`. Internal details, stack traces, SQL, and file paths never reach
  the client.
- Cross-tenant access returns 404, not 403, so resource existence is not disclosed.
- Do not log and return the same error; log once at the boundary that handles it.

## 4. API design standards

- Base path `/api/v1`. Breaking changes require `/api/v2` and a deprecation window of
  at least two minor releases, announced with `Deprecation` and `Sunset` headers.
- Resource-oriented, plural nouns: `/orgs/{orgSlug}/projects/{projectId}/runs`.
- JSON fields camelCase; timestamps RFC 3339 UTC; IDs are opaque strings (ULIDs).
- Pagination: cursor-based (`?cursor=&limit=`), max `limit` 100, response includes
  `nextCursor`.
- Filtering and sorting via explicit, allow-listed query params only.
- `Idempotency-Key` header supported on POSTs that trigger runs, syncs, or deployments.
- Optimistic concurrency with `ETag` and `If-Match` on mutable resources.
- Every operation in OpenAPI declares its security scheme, required permission
  (`x-kiln-permission`), and all error responses.
- Long-running actions return `202 Accepted` with a status resource.

## 5. Configuration

- 12-factor: configuration from environment variables prefixed `KILN_`, optionally
  from a file for non-secret values. Secrets may also come from files
  (`KILN_DB_PASSWORD_FILE`) for Kubernetes secret mounts.
- All configuration is parsed into one typed struct in `internal/platform/config`
  and validated at startup. Invalid config fails fast with a clear message and never
  prints secret values.
- Secure defaults: TLS on, shell executor off, fork-PR secrets off, public signup off.
- No reading environment variables outside `platform/config`.

## 6. Observability

- **Logging:** `log/slog`, JSON in production. Every log line in a request context
  carries `request_id`, `trace_id`, and `org_id` where known. Levels: `Debug` for
  developer detail, `Info` for state changes, `Warn` for recovered problems, `Error`
  for failures needing attention. No PII or secrets; use the redaction helpers.
- **Tracing:** OpenTelemetry. Spans on every service method, outbound HTTP/gRPC call,
  DB transaction, and queue publish/consume. Propagate W3C trace context to runners.
- **Metrics:** Prometheus via OpenTelemetry. RED metrics per endpoint; queue depth,
  lease age, run duration histograms, reconcile loop latency, and sync failures.
  Label cardinality must be bounded (no IDs as labels).
- **Health:** `/healthz` (process alive) and `/readyz` (dependencies reachable).

## 7. Resilience

- Every outbound call has a timeout, set via `platform/httpclient` or gRPC deadlines.
- Retries only for idempotent operations, with exponential backoff and jitter, and a
  cap on attempts.
- Queue consumers are idempotent: processing the same message twice has no extra effect.
- Graceful shutdown: stop accepting work, drain in-flight requests and leases, then exit,
  all bounded by a shutdown timeout.
- Bulkheads: the GitOps reconciler and the CI scheduler use separate worker pools so
  one cannot starve the other.

## 8. Concurrency (Go)

- Every goroutine has an owner, is started with a context, and has a clear exit path.
- Prefer `errgroup.Group` with context for fan-out.
- Shared mutable state is guarded by a mutex owned by a single struct; no mutexes
  passed around by value.
- Channels have a documented owner who closes them.
- All tests run with `-race` in CI.

## 9. Database

- Access only through sqlc queries. Every query on tenant data filters by `org_id`.
- Transactions are opened in the service layer via a `store.WithTx` helper.
- Migrations are forward-only in production, backward-compatible across one release
  (expand/contract), with both Up and Down written.
- New query paths ship with the supporting index; include `EXPLAIN` notes in the PR
  for queries on large tables (runs, jobs, audit events).
- No `SELECT *` in queries.

## 10. Testing

| Level | Tool | Expectation |
|---|---|---|
| Unit | `go test`, Vitest, Jest | Fast, no network; table-driven in Go |
| Integration | testcontainers (Postgres, NATS, MinIO) | Store, queue, and object storage behavior |
| Contract | OpenAPI validation in tests | Responses conform to the spec |
| E2E | docker-compose stack | Webhook → run → logs → status; GitOps sync |
| Fuzz | Go native fuzzing | Pipeline parser, webhook payload parsing, log masker, path resolver |
| Security | authz matrix tests | Every endpoint × role × cross-org |

- Coverage: 80% overall floor; 85% for `auth`, `secrets`, `webhooks`, `engine/spec`,
  and runner executors. Coverage must not decrease in a PR.
- Tests are deterministic: inject `Clock` and random sources; no `time.Sleep` for
  synchronization.
- Test names describe behavior: `TestScheduler_LeaseExpired_RequeuesJob`.

## 11. Frontend (web, desktop, mobile)

- TypeScript `strict`, no `any`, no non-null assertions without a comment.
- All API access via `@kiln/api-client`; no ad-hoc `fetch` to the API.
- Server state in TanStack Query; UI state local; no global store without an ADR.
- Shared business-free logic in `packages/core`; DOM components in `packages/ui`.
- Accessibility: WCAG 2.1 AA for web and desktop; keyboard navigation for every
  action; axe checks in component tests.
- Every async UI shows loading, empty, and error states.
- Mobile: supports offline read of last-known run status; destructive and approval
  actions require confirmation.

## 12. Documentation

- Every exported Go identifier has a doc comment starting with its name.
- Each package has a `doc.go` explaining its responsibility.
- Architecture decisions are recorded as ADRs (context, decision, consequences,
  security considerations).
- User-facing behavior changes update the docs site in the same PR.

## 13. Code review

- `CODEOWNERS` defines owners per area. Security-sensitive paths (`auth`, `secrets`,
  `webhooks`, `runner`, `proto`, `gitops`, `deploy`, `.github/workflows`) require two
  approvals, one from the security owners group.
- PRs are small (target under 400 changed lines excluding generated code) and use the
  PR template, including the security checklist.
- Reviewers check correctness, tests, authorization, error handling, logging hygiene,
  and backward compatibility before style.

## 14. Versioning and releases

- Semantic Versioning for the server, runner, CLI, and API.
- Changelog generated from Conventional Commits.
- Release artifacts are reproducible, signed, and ship with an SBOM and provenance
  (see security standards).

## 15. Licensing

- Project license: Apache-2.0. Every source file carries
  `SPDX-License-Identifier: Apache-2.0`.
- Contributions require DCO sign-off (`git commit -s`).
- Dependency licenses must be on the allowlist in the security standards.
