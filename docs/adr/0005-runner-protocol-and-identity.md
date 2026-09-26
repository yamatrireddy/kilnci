<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0005: Runner protocol, identity, and job leasing

- **Status:** Accepted (Phase 1 plan approved by the maintainer, 2026-09-26)
- **Date:** 2026-09-26
- **Boundary:** B2 (control plane ↔ runner)

## Context

Runners execute jobs on hosts Kiln does not fully trust (threat model §4:
"compromised runner host"). CLAUDE.md invariant 2 says runners pull and the
server never pushes; security-standards §3 says runners authenticate with a
single-use registration token exchanged for a short-lived, auto-rotated mTLS
client certificate; §4 says a runner principal may only lease jobs for its
labels, stream logs for its own leases, and report their results.

The protocol must stay usable in single-binary mode (invariant 7), must let an
old runner keep working against a new server for one minor version, and must
not give a stolen runner credential more than one runner's worth of access.

## Decision

1. **Transport.** gRPC over TLS 1.3 on a dedicated listener
   (`KILN_RUNNER_ADDR`, default `:9443`), separate from the HTTP API. Runners
   dial out; the server never opens connections to runners. All RPCs are
   unary and runner-initiated (`Lease` long-polls for up to 25 s).

2. **Kiln runner CA.** The server holds an internal ECDSA P-256 CA
   (`KILN_RUNNER_CA_DIR` with `ca.crt`/`ca.key`, created by
   `kiln-server runner-ca init`). It signs:
   - the gRPC server certificate (issued in memory at startup for
     `KILN_RUNNER_HOSTNAMES`, 30-day validity, re-issued daily), and
   - runner client certificates (24-hour validity).
   Runners pin this CA (it is given to them out of band with the
   registration token) and trust nothing else, so a public CA mis-issuance
   cannot intercept runner traffic (T-15). If the CA directory is not
   configured, the runner listener is disabled and the server logs why.

3. **Registration.** An org admin creates a registration token through the
   API (`kiln_rrt_` + 256 random bits, SHA-256 stored, single use, at most
   24 hours, labels and trust level fixed at creation, audited). The runner
   generates its own key pair, and calls `Register` with the token and a
   PKCS#10 CSR. The server verifies the CSR signature (proof of possession),
   ignores every requested subject and extension, and issues a certificate
   whose subject is fixed by the server: `CN=<runner ID>`, URI SAN
   `kiln://orgs/<org ID>/runners/<runner ID>`, `ExtKeyUsage=ClientAuth` only.
   The runner's private key never leaves the host.

4. **Renewal and revocation.** Runners call `RenewCertificate` (mTLS) with a
   new CSR once a certificate is a quarter to half through its lifetime
   (earlier renewals are rate-limited). Every authenticated RPC loads the
   runner row, so revocation takes effect on the next call, and lease grants
   re-check the runner row, so it also cuts off a long-poll already in
   progress. Serial rules (security review):
   - The **current** serial may do anything, including renew.
   - The immediately **previous** serial is accepted for 5 minutes after a
     renewal so in-flight calls finish. A renewal from it with the *same
     key* as the new certificate is a retry after a lost response and gets
     the current certificate again (the key's SPKI hash is stored).
   - Any other verified, unexpired certificate for a live runner (previous
     serial after the grace period, or a renewal with a different key)
     means two parties hold the runner's credentials: the runner is revoked
     and the reuse is audited. The runner persists its new key before
     asking for renewal so a crash cannot turn a retry into reuse.

5. **Method policy (deny by default, invariant 9).** A gRPC interceptor maps
   every method to one rule: `Register` requires a registration token and no
   certificate; every other method requires a verified client certificate
   of a live runner. The server refuses to start if a registered method has
   no rule (mirrors the HTTP router's startup check).

6. **Runner principal.** `authz.KindRunner` with the runner ID, its org, its
   labels, and its trust level, all loaded from the database (never from the
   certificate beyond the runner ID). It can:
   - lease a queued job of **its own org** whose required labels are a subset
     of the runner's labels and whose trust requirement the runner meets;
   - heartbeat, append logs to, and complete **only jobs it currently leases**
     (lease ID + runner ID match and the lease has not expired).
   It cannot call the HTTP API.

7. **Leases (T-14, T-16).** A lease is a random 128-bit ID plus an expiry
   (default 60 s) renewed by `Heartbeat`. Results are accepted only with the
   current lease ID from the leasing runner, before expiry. Expired leases
   are reaped: the job is re-queued up to its retry budget, otherwise failed.
   Jobs also have a hard timeout; heartbeats report cancellation and timeout
   so the runner stops the job. Grants lock the run, then the runner, then
   compare-and-swap the job, so two runners can never hold the same job and
   a runner never exceeds its capacity (default 1 concurrent job). A lease
   that was granted but could not be delivered is released without spending
   an attempt. Each runner may have at most two `Lease` long-polls in flight,
   polls back off from 250 ms to 4 s, and the listener caps connections, so
   one runner credential cannot multiply database load.

8. **Versioning (T-17).** Every request carries `protocol_version`. The server
   accepts the current and previous minor protocol versions and rejects
   anything else with `FAILED_PRECONDITION`. `proto/` changes are additive
   only (never renumber or reuse fields).

9. **Trust levels.** Runners are `untrusted` (default) or `trusted`. A job is
   eligible for a trusted runner only if its run is trusted; untrusted jobs
   (fork PRs, and any run whose trust was not positively established) never
   run on trusted runners (SS §8), enforced in the lease query and by a
   database constraint that a job's trust equals its run's. Trusted jobs may
   run on untrusted runners, but because an untrusted host may have been
   poisoned by earlier fork jobs, **secrets are delivered only to trusted
   runners** and deploy provenance (Phase 3) is accepted only from trusted
   runners: a job that needs either is routed to trusted runners only
   (Phase 2). Cache scoping by trust level also arrives in Phase 2.

## Consequences

- New tables: `runners`, `runner_registration_tokens`; new columns on jobs
  for leases. New packages: `internal/rpc` (gRPC transport),
  `internal/service/runners`, `internal/platform/pki`, and the `proto/` and
  `runner/` modules.
- Operators must distribute `ca.crt` to runner hosts and open the runner port.
- `--embedded` mode serves the runner listener from the same process.
- New dependencies: `google.golang.org/grpc` and
  `google.golang.org/protobuf` (both Apache-2.0/BSD-3, already indirect).
  `buf` and the protoc plugins are pinned in `tools/go.mod`.

## Security considerations (STRIDE, B2)

- *Spoofing (T-12):* registration tokens are single-use, short-lived, hashed,
  and audited; certificates are issued only after proof of possession; the
  server certificate is pinned to the Kiln CA on the runner side.
- *Tampering (T-14):* results are bound to the lease; a runner cannot report
  on a job it does not hold. Log appends are idempotent per sequence number,
  so replays cannot duplicate or reorder output.
- *Repudiation:* registration, deletion, and token creation are audit-logged;
  every lease records the runner ID.
- *Information disclosure (T-13, T-15):* TLS 1.3 only, mutual authentication,
  no plaintext fallback. A runner sees only jobs for its org and labels.
- *Denial of service (T-16):* lease expiry, job timeouts, long-poll cap,
  per-runner rate limits, message size limits (4 MiB receive).
- *Elevation of privilege (T-13):* the runner principal has no HTTP API
  access and no cross-org scope; revocation is checked on every call; trusted
  runners never receive fork jobs.
