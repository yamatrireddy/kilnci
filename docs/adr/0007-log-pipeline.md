<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0007: Log pipeline — object storage, live bus, and Server-Sent Events

- **Status:** Accepted (maintainer decision, 2026-09-26)
- **Date:** 2026-09-26
- **Amends:** CLAUDE.md architecture invariant 4 ("live tails over NATS →
  WebSocket" becomes "live tails over NATS → Server-Sent Events")
- **Boundaries:** B1 (clients read logs), B2 (runners write logs)

## Context

Invariant 4: logs never go into PostgreSQL; chunks go to object storage; live
tails flow over NATS to clients; secrets are masked by the runner before any
byte leaves it. Build logs can contain leaked secrets and internal details
(A10) and attacker-controlled bytes (ANSI escapes, HTML) that the web client
must render safely (T-09). Log fan-out is a resource-exhaustion vector (T-10).

The Go standard library has no WebSocket implementation. Live tails are
strictly server → client, so the bidirectional WebSocket protocol buys
nothing, while it would add a dependency (or hand-written framing that needs
SHA-1) and an extra upgrade path outside the router's authentication,
Origin, and CSRF model.

## Decision

1. **Write path (B2).** The runner sends `AppendLogs(job, lease, seq, data)`
   with chunks of at most 256 KiB, already masked. The server checks the
   lease, then writes the chunk to object storage at
   `orgs/<org>/runs/<run>/jobs/<job>/<seq, zero-padded>` and records chunk
   metadata (sequence, size, SHA-256 of the content, object key) — never
   content — in PostgreSQL. Appends are idempotent per `(job, seq)`: a
   replay with identical content is acknowledged, a replay with different
   content is rejected. Sequence numbers must be contiguous from 0 and at
   most 16 384 chunks are accepted per job, so tiny chunks cannot exhaust
   metadata rows or object counts. A per-job cap (default 64 MiB) truncates
   further output with a marker.

2. **Object storage.** `internal/platform/objstore` with two backends:
   `fs` (a directory; the default and the `--embedded` backend, paths built
   only from server-generated IDs) and `s3` (S3-compatible, via `minio-go`,
   using the `platform/httpclient` transport so SSRF rules apply). Buckets
   are private; the API streams logs itself rather than handing out
   pre-signed URLs (T-45).

3. **Live bus.** `internal/platform/bus` publishes "chunk appended" and "job
   finished" events per job: NATS (`nats.go`) when `KILN_NATS_URL` is set,
   otherwise an in-process implementation (single-replica and `--embedded`).
   Events carry IDs only; readers fetch chunk content from object storage, so
   the bus never becomes a second log store. NATS connections use TLS and
   credentials (user/password or NKey from a file), and subjects are scoped
   by org (`kiln.orgs.<org>.jobs.<job>.logs`).

4. **Read path (B1).**
   - `GET …/jobs/{jobId}/logs` returns the stored log as
     `text/plain; charset=utf-8` with `nosniff`,
     `Content-Security-Policy: sandbox`, and
     `Content-Disposition: attachment` semantics for direct navigation.
   - `GET …/jobs/{jobId}/logs/stream` is a **Server-Sent Events** stream
     (`text/event-stream`) through the normal router: same authentication,
     same resource authorization (`logs:read` on the job's project), same
     rate limits. It replays stored chunks from `Last-Event-ID`, then follows
     the bus until the job finishes, and closes after a server-side maximum
     duration. Each event carries base64 data so arbitrary bytes cannot break
     SSE framing. Concurrent streams per principal are capped.

5. **Rendering.** The web client never inserts log bytes as HTML. The
   sanitizing log viewer parses SGR color/style codes into React spans and
   drops every other escape sequence (OSC links, cursor movement, title
   changes) and control character (T-09).

## Consequences

- Invariant 4 in CLAUDE.md is updated to say Server-Sent Events.
- New dependencies: `github.com/nats-io/nats.go` (Apache-2.0) and
  `github.com/minio/minio-go/v7` (Apache-2.0). No WebSocket dependency.
- Horizontally scaled servers need NATS; the in-process bus only reaches
  streams on the same replica.

## Security considerations (STRIDE)

- *Spoofing:* only the leasing runner can append (B2, ADR-0005); readers are
  authenticated principals with `logs:read` on the specific project.
- *Tampering:* appends are lease-bound and idempotent; chunk keys are built
  from server IDs only, never from runner-supplied paths.
- *Repudiation:* chunk metadata records the lease and runner.
- *Information disclosure (A10, T-04):* cross-org reads get 404; logs are
  never in PostgreSQL, traces, or server logs; masking happens on the runner.
- *Denial of service (T-10):* per-job size cap, chunk size limit, capped
  concurrent streams and maximum stream duration, per-principal rate limits.
- *Elevation of privilege (T-09):* log bytes are data, rendered through the
  sanitizing viewer under a strict CSP; the raw endpoint is `sandbox`ed.
