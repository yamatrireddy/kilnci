<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0006: Job sandbox and the Docker executor

- **Status:** Accepted (Phase 1 plan approved by the maintainer, 2026-09-26)
- **Date:** 2026-09-26
- **Boundary:** B3 (runner → job sandbox)

## Context

Job code is hostile by assumption (security-standards §8). Invariant 3 says
every step runs in a container and the shell executor is opt-in, disabled by
default, and blocked for fork PRs. Phase 1 ships one executor: Docker.

## Decision

1. **One container per job, one exec per step.** The runner creates a job
   container from the job's `image` with an idle entrypoint and runs each step
   with `docker exec` as `["/bin/sh", "-e", "-c", <run>]`. The script is the
   pipeline author's own code and runs only inside the sandbox; the runner
   never evaluates it on the host. Pipeline expressions are not interpolated
   (the spec rejects `${{`); event data (branch, PR title, SHA) reaches steps
   only as `KILN_*` environment variables (T-24).

2. **Hardened defaults (T-19, T-26)**, not configurable per pipeline:
   - `User: 65532:65532` (non-root, and unlikely to be a person's UID on
     the host; changed from 1000 after the Phase 1 security review),
     `HOME=/tmp/home`;
   - `CapDrop: ALL`, `SecurityOpt: no-new-privileges`, the runtime's default
     seccomp and AppArmor profiles, `Privileged: false`;
   - no host network, PID, IPC, or UTS namespace; no bind mounts from the
     host; the Docker socket is never mounted;
   - `Init: true`; limits on memory (default 4 GiB, no swap), CPU (default
     2), PIDs (default 1024), and disk (default 10 GiB for each
     container's writable layer via `StorageOpt size` and for the
     workspace volume via the local driver's `size` option; it needs
     `overlay2` on XFS with `pquota`, which the runner checks at startup and
     before each job, failing closed unless the operator passes
     `--job-disk-limit=off`); a tmpfs `/tmp`;
   - a dedicated bridge network per job, removed afterwards.
   Runner operators may lower limits; raising privileges needs a code change.

3. **Workspace.** A per-job named volume is mounted at `/workspace`. It is
   populated by a clone container (a pinned `alpine/git` image digest,
   same hardening, running as the same UID) that fetches exactly the run's
   commit SHA (`git fetch --depth=1 origin <sha>`; refs and branch names are
   never passed to git, and every argument list ends options with `--`).
   A short-lived, read-only repository credential (if any) reaches only the
   clone container, and only as an `http.extraHeader` supplied through
   `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` environment
   variables for that single fetch: never in the remote URL, never through a
   credential helper, never written to `.git/config`, and without submodule
   recursion. Pipeline `env` never reaches the clone container (it could set
   `GIT_*` variables). Before the job container starts, the runner scans the
   volume for the credential and fails the job closed if it appears anywhere
   (security review). The volume, containers, and network are removed when
   the job ends, whatever the outcome (T-23).

4. **Images.** Every job pulls anonymously, so a fork PR cannot use the
   runner host's registry credentials to pull an org's private images.
   Registry credentials for trusted jobs may come later; digest pinning
   and plugin capabilities are Phase 4 (T-25). Because `dockerd` pulls from
   the host's network namespace (outside the job's egress rules), the runner
   refuses images from registries on loopback, private, link-local, CGNAT,
   or metadata addresses, literal or resolved, unless the operator
   allow-lists the exact registry (T-60).

5. **Masking (T-27).** The runner masks every sensitive value it knows (the
   clone credential now; secrets in Phase 2) in the combined stdout/stderr
   stream before any byte leaves the runner, including base64 in each
   alignment (also when wrapped into lines of 16 or more characters, as
   `base64` and PEM output are), URL-encoded, lower- and upper-case hex, and
   JSON-escaped forms, per-line pieces of multi-line values, and matches
   split across chunk boundaries; output is the same however it is split
   into writes. To bound memory and output delay, the runner refuses a job
   whose values exceed 64 KiB each or 256 KiB in total, and masks wrapped
   base64 only for values up to 4 KiB. Known gaps: values shorter than 4
   bytes, base64 wrapped narrower than 16 columns, up to 3 characters at a
   wrapped line's edge, and any encoding not listed. Masking is a safety
   net, not a boundary.

6. **Shell and Kubernetes executors.** The shell executor is not built
   (so it cannot be enabled by accident). Kubernetes (PSS `restricted`) is
   Phase 4.

7. **Egress (T-20, T-21).** Blocking cloud metadata and private ranges from
   job containers requires host firewall rules the runner cannot portably
   set. The runner documentation ships the required `iptables`/`nftables`
   rules for the `DOCKER-USER` chain, and the runner refuses to start unless
   the operator acknowledges them with `--egress-policy=host-enforced`
   (or explicitly accepts the risk with `--egress-policy=none`, which is
   logged on every job).

## Consequences

- New module `runner/` (agent + `executor/docker`), new dependency
  `github.com/moby/moby/client` (Apache-2.0, already indirect via
  testcontainers). Images that require root at build time must be adapted
  (e.g. use rootless tooling); this is intended.
- Integration tests need Docker.

## Security considerations (STRIDE, B3)

- *Spoofing:* not applicable inside the sandbox; the job has no Kiln
  credential. The runner's mTLS key is on the host, outside any mount.
- *Tampering (T-23):* per-job volumes and networks; nothing survives the job.
  Caches (T-22) are not offered until Phase 2 scopes them by trust.
- *Repudiation:* every step's exit code and timing are reported under the
  lease.
- *Information disclosure (T-18, T-27):* Phase 1 delivers no secrets; the
  clone credential is confined to the clone container and masked.
- *Denial of service (T-26):* CPU, memory, PID, disk, and time limits; the
  job timeout is enforced both by the runner and by the server's lease
  reaper. Output the runner cannot upload is replaced by a marker in the
  log rather than dropped silently.
- *Elevation of privilege (T-19):* non-root, no capabilities,
  no-new-privileges, default seccomp/AppArmor, no Docker socket, no
  privileged mode. Kernel 0-days remain an accepted residual risk (threat
  model §9); ephemeral runner hosts are recommended.
