<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0008: GitHub integration, webhook ingest, and run triggers

- **Status:** Accepted (maintainer decisions, 2026-09-26)
- **Date:** 2026-09-26
- **Boundaries:** B1 (webhook ingest), B6 (GitHub API), B3 (what code runs)

## Context

Runs are triggered by pushes and pull requests. Webhook ingest is one of the
few unauthenticated routes (invariant 9) and must verify a signature before
parsing (SS §11, T-01). Fork PR authors control pipeline YAML, code, and every
event field of their PR (threat model §4, S1). Kiln posts commit statuses back
to GitHub (T-43) with an app whose permissions must be minimal (T-42). In a
multi-tenant instance, one Kiln org must never be able to attach another
tenant's repositories (S2).

## Decision

1. **GitHub App.** Kiln authenticates as one GitHub App per instance
   (`KILN_GITHUB_APP_ID`, `KILN_GITHUB_APP_PRIVATE_KEY_FILE`,
   `KILN_GITHUB_WEBHOOK_SECRET[_FILE]`, `KILN_GITHUB_API_URL` for GHES).
   Required permissions: `contents: read`, `metadata: read`,
   `pull_requests: read`, `statuses: write`. App JWTs (RS256, 9-minute
   lifetime) are exchanged for installation tokens restricted to the single
   repository and the permissions each operation needs, cached until five
   minutes before expiry. All GitHub calls go through `platform/httpclient`.

2. **Installation binding (maintainer decision).** An **instance admin** binds
   a GitHub installation ID to exactly one Kiln org
   (`/api/v1/admin/github-installations`, audited). Org admins can link a
   project only to a repository that belongs to one of *their* org's
   installations — verified live against GitHub — and each repository can be
   linked to at most one project on the instance. Webhooks for unbound
   installations or unlinked repositories are acknowledged and dropped.

3. **Ingest (`POST /api/v1/webhooks/github`, public).**
   - Body limit 5 MiB; `X-Hub-Signature-256` HMAC-SHA256 over the raw body,
     compared with `hmac.Equal`, **before** any parsing.
   - `X-GitHub-Delivery` is recorded with a unique constraint; a replayed
     delivery ID is acknowledged without effect (T-01 replay control;
     GitHub does not sign a timestamp).
   - Only `push`, `pull_request` (`opened`, `synchronize`, `reopened`), and
     `ping` are accepted; the verified body is stored in a queue table and
     the handler returns `202`. A worker pool processes the queue
     (`FOR UPDATE SKIP LOCKED`, bounded retries), so webhook floods cannot
     block the API (T-10).

4. **Triggers.** The worker fetches `.kiln/pipeline.yaml` at the exact commit
   SHA through the contents API, parses it with `engine/spec`, checks the
   pipeline's `on:` filters, and creates the run and its jobs in one
   transaction. A pipeline that fails to parse produces a failed run with the
   validation errors, so authors see why. Developers can also start a run on
   a branch through the API (`Idempotency-Key` supported).

5. **Trust and fork PRs (S1).** A PR is a fork PR when its head repository
   differs from the base repository. Fork runs are **untrusted**: they never
   run on trusted runners, never receive secrets (Phase 2), and by default
   start in `awaiting_approval` until a developer of the org approves them
   (audited). Event fields (titles, branch names) are stored and shown as
   untrusted text and reach jobs only as environment variables.

6. **Commit statuses.** On run state changes, a status (`pending`, `success`,
   `failure`, `error`) with context `kiln/<project slug>` and a link to the
   run is written to an outbox table in the same transaction and delivered by
   a worker with retries. Only the control plane holds the app key, so
   statuses cannot be forged by jobs (T-43).

7. **Pipeline lint API (maintainer decision).** `POST /api/v1/pipelines/lint`
   parses a submitted pipeline with the same loader and returns validation
   errors. It is authenticated and rate-limited, reads no tenant data, and
   backs `kiln lint` in the CLI, so there is exactly one parser.

## Consequences

- New tables: `github_installations`, `repositories`, `webhook_deliveries`,
  `commit_status_outbox`. New packages: `internal/webhooks/github` (verify +
  parse), `internal/vcs/github` (App client), `internal/service/triggers`.
- GitHub is the only provider in Phase 1; GitLab and Bitbucket follow the
  same shape.
- Local development needs a GitHub App or the fake GitHub server used by the
  tests.

## Security considerations (STRIDE)

**B1 webhook ingest**
- *Spoofing (T-01):* HMAC verified in constant time over the raw body before
  parsing; unknown events rejected; delivery IDs deduplicated.
- *Tampering:* payload fields are used only after verification and only as
  data; refs and SHAs are validated against strict patterns.
- *Repudiation:* deliveries are recorded with their outcome.
- *Information disclosure:* the endpoint returns no tenant information and
  the same response whether or not a repository is linked.
- *Denial of service (T-10):* 5 MiB limit, per-IP rate limit, async queue
  with a bounded worker pool.
- *Elevation of privilege:* the handler can only enqueue; it cannot reach any
  other tenant data.

**B6 GitHub API**
- Installation tokens are scoped to one repository and the minimum
  permissions, short-lived, and never logged or persisted (T-42). The App
  private key is read from a file and held only in memory.

**Tenant isolation (S2)**
- Installation → org binding by instance admins and one-project-per-repo
  prevent an org from attaching another tenant's repositories.

**B3 what code runs (S1, T-18, T-24)**
- Fork PRs require approval, run untrusted, and get no secrets; expressions
  are never interpolated into scripts.
