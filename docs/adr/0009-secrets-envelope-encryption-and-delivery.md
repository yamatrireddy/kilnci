<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0009: Secrets: envelope encryption, scopes, and delivery to jobs

- **Status:** Proposed
- **Date:** 2026-09-27
- **Boundaries:** B2 (secrets in job leases), B3 (secrets inside the job
  sandbox), B6 (Vault Transit), data stores (T-44, T-47)

## Context

Pipelines need credentials (registry passwords, cloud keys, deploy tokens).
They are Kiln's most valuable asset (A1) and the main prize for a fork PR
author (S1, T-18), a developer without deploy rights, or a compromised
runner host (S3, T-12, T-13). Security standards §7 fixes the outline:
envelope encryption with keys outside the database, write-only API,
decryption only when building a lease for an authorized runner, secrets
restricted to protected branches, no secrets for fork PRs. ADR-0005 §9
already says secrets go to trusted runners only, and the runner protocol
already carries per-step environment variables and `mask_values` (masked
before any byte leaves the runner, T-27). This ADR decides the rest.

"Trusted run" (ADR-0008 §5) only means "not from a fork": every push to any
branch and every same-repository PR is trusted. That is enough to pick a
runner pool, but **not** enough to hand out credentials, because anyone with
push access can create a branch with any name. Delivery therefore needs a
stronger condition, defined in §5.

## Decision

1. **Key hierarchy.**
   - A **key-encryption key (KEK)** lives outside PostgreSQL, in one of the
     providers below. Kiln never stores it.
   - Each org has a **data-encryption key (DEK)**: 32 random bytes from
     `crypto/rand`, stored only wrapped by the KEK, with a version number.
     An org may have several DEK versions; exactly one is active for new
     writes.
   - Each secret value is sealed with AES-256-GCM under its org's DEK, with
     a fresh random 96-bit nonce per write. The **additional authenticated
     data** binds the ciphertext to its row: org ID, scope kind (`org` or
     `project`), scope ID, secret name, DEK version, and a **value version**
     that increases on every write. A ciphertext copied into another row,
     scope, org, or name fails to open, and an older ciphertext of the same
     secret (for example a leaked value that was just rotated) cannot be
     restored in place (T-62).
   - Plaintext DEKs are cached in memory for at most 5 minutes so a busy
     scheduler does not call Vault on every lease; values are never cached.
   - Only the standard library (`crypto/aes`, `crypto/cipher`, `crypto/hkdf`,
     `crypto/rand`) is used.

2. **KEK providers** (`KILN_SECRETS_PROVIDER`).
   - `local`: a 32-byte key, base64-encoded, from `KILN_MASTER_KEY_FILE`.
     `KILN_MASTER_KEY` in the environment is accepted only with
     `--embedded` or in development, because the environment leaks through
     process listings, orchestrator UIs, and crash reports. Two subkeys are
     derived with HKDF-SHA256: a wrapping key (AES-256-GCM, with the org ID
     as additional data) and a key-ID key, whose truncated output names the
     KEK in the database without revealing it. An optional
     `KILN_MASTER_KEY_PREVIOUS_FILE` is accepted for unwrapping only, for
     rotation (§6).
   - `vault`: HashiCorp Vault Transit `encrypt`/`decrypt`/`rewrap` on the
     key named by `KILN_VAULT_TRANSIT_KEY`, at `KILN_VAULT_ADDR`, with a
     token from `KILN_VAULT_TOKEN_FILE` (re-read on each call, at most
     8 KiB, so a Vault agent can renew it). The org ID is passed as the
     Transit derivation `context`.
     - **Key checks at startup (fail closed):** Kiln reads the key's
       settings and refuses to start unless it is `derived` (otherwise
       Vault ignores the context and DEKs are not bound to their org),
       not `exportable`, and without `allow_plaintext_backup`. It warns
       when `deletion_allowed` is set.
     - **Minimal Vault policy:** `update` on `<mount>/encrypt/<key>`,
       `<mount>/decrypt/<key>`, and `<mount>/rewrap/<key>`, and `read` on
       `<mount>/keys/<key>`. Nothing else: no `create` on `keys/` (so
       Transit cannot create a key with default settings on first use), no
       `export/`, no `config`.
     - **Dedicated HTTP client.** Vault is reached through its own
       `platform/httpclient` instance with its own private-range allowlist
       (`KILN_VAULT_ALLOWED_PREFIXES`) and optional CA bundle
       (`KILN_VAULT_CACERT_FILE`). Operators never widen the global
       `KILN_EGRESS_ALLOWED_PREFIXES`, which user-influenced URLs go
       through (T-40). The client **never follows redirects**: a redirect
       would resend the token, and on 307/308 a plaintext DEK, to another
       host. A 3xx is an error telling the operator to point
       `KILN_VAULT_ADDR` at the active node or a forwarding load balancer.
     - No new dependency: plain JSON over HTTPS.
   - **Cloud KMS (AWS, GCP, Azure) is deferred.** Their SDKs are large new
     dependencies; the provider interface (wrap/unwrap/rewrap with an org
     context) is shaped so they can be added later without schema changes.
   - No provider configured means the secrets feature is off: the API returns
     `503` with a problem type saying so, and pipelines that declare secrets
     fail with a clear reason. Kiln never generates or defaults a master
     key, and `--embedded` mode keeps working without one (invariant 7).
   - At startup, Kiln counts wrapped DEKs whose key ID the provider does
     not know and refuses to start if there are any, instead of failing on
     the first lease.

3. **Scopes and names.**
   - Secrets belong to an **org** or to a **project**. A project secret
     shadows an org secret of the same name for that project. Environment
     scope arrives with GitOps (Phase 3).
   - **Org secrets name the projects that may use them** (a list of
     project IDs, or an explicit "all projects"). The default for a new org
     secret is no projects, so a member of one small project cannot pull
     every org-wide credential into their pipeline.
   - Names follow the environment-variable rules of the pipeline spec
     (`^[A-Za-z_][A-Za-z0-9_]{0,127}$`, no `KILN_` prefix), unique per
     scope, at most 500 per scope. Names that change how the shell or the
     dynamic loader behaves are rejected: `PATH`, `HOME`, `SHELL`, `IFS`,
     `ENV`, `BASH_ENV`, `CDPATH`, `PS4`, `LD_*`, `DYLD_*`, `GIT_*`,
     `SSH_*`. A secret and a step `env:` entry may not share a name within
     one step; the pipeline fails validation rather than silently picking
     one.

4. **Values.**
   - Write-only. The API accepts a value on create or replace and never
     returns it; reads return metadata (name, scope, restrictions, value
     version, `masked`, created/updated time and actor).
   - **Size: 1 byte to 64 KiB**, no NUL bytes, valid UTF-8. 64 KiB per
     value and 256 KiB per job match the limits the runner already enforces
     before masking.
   - **Short values (maintainer decision, 2026-09-27):** values under 4 bytes
     are accepted with a warning, because the runner masker does not mask
     them (T-27 residual). The create/replace response carries a `warnings`
     entry saying the value will not be masked in logs, the metadata records
     `masked: false` so the UI can keep showing it, and the audit event
     notes it.
   - Every create, replace, and delete is audit-logged with the actor,
     scope, and name, never the value (T-11, T-47).

5. **Delivery to jobs.**
   - **Per step, opt-in.** A step lists the secrets it needs:
     `secrets: [NAME, ...]` on the step (at most 50 per job). Values are
     placed in **that step's** environment only, never the job-wide
     environment, so other steps of the job, and plugin steps (Phase 4, which
     receive only what their `with:` passes explicitly), never see them
     (T-25). Nothing is delivered implicitly.
   - **Protected branches.** By default a secret is delivered only to runs
     from a **push to a branch that is protected at the VCS**. The GitHub
     trigger records, at run creation, whether the pushed branch is
     protected (the branches API's `protected` flag, available with the
     App's existing `metadata: read` permission); the run stores that fact,
     and it cannot change afterwards. Pull-request runs, including
     same-repository ones, and manual runs on unprotected branches never
     count as protected.
   - **Branch patterns** narrow delivery further: up to 20 per secret,
     either exact branch names or a prefix ending in `/*` (`release/*`
     matches `release/1.2` and `release/1/2`; `*` alone matches any
     protected branch). Tags are not branches and never match. A pattern
     never widens delivery beyond protected branches.
   - **Opt-in widening.** A secret can be marked `allowUnprotected: true`
     (org or project admins, audited), which delivers it to every trusted
     run of its scope, including same-repository PRs. The UI and API warn
     that anyone with push access can then read it. Fork and other
     untrusted runs are still excluded.
   - **Trusted runners only.** A job with any step that declares secrets
     **in a run eligible for them** is marked as requiring a trusted runner
     at run creation; the lease query then offers it only to trusted
     runners (ADR-0005 §9). Desktop-embedded local runners are never
     registered as trusted by default, so secrets do not land on laptops.
   - **Untrusted runs never get secrets.** A job in an untrusted run (fork
     PRs, anything whose trust was not positively established) runs without
     them on untrusted runners, exactly as today, and
     `KILN_SECRETS_WITHHELD=true` tells the script why its variables are
     missing. There is no setting that sends secrets to fork runs in this
     phase. A trusted but ineligible run (unprotected branch) behaves the
     same way.
   - **Resolved at lease time.** Secrets are resolved and decrypted while
     building the lease: the runner must be trusted, unrevoked, and belong
     to the job's org; the run must be trusted and eligible (protected
     branch, or the secret allows unprotected); and each secret's project
     allow-list and branch patterns must match. A declared secret that is
     missing or not permitted fails the job with a reason naming the
     secret, rather than running with a missing variable.
   - **Delivery is audited.** Each lease that resolves secrets records an
     audit event with the run, job, runner, and the secret names and value
     versions delivered, never values, so "who could have seen this
     credential?" has an answer (T-47).
   - **Transport and handling.** Values travel to the runner only inside the
     mTLS lease response, and every value is also sent in `mask_values`.
     They are never written to the run, job, or log tables, never published
     to NATS, and lease payloads are never logged by gRPC interceptors or
     recorded in traces.
   - **Residue on reused runners.** A trusted runner that is not ephemeral
     can keep files, image layers, or caches from one project's job for a
     later trusted job of another project in the same org. The runner
     docs recommend ephemeral trusted runners or per-project trusted pools
     (labels); this is recorded as a residual risk.

6. **Rotation.**
   - *KEK rotation (routine):* configure the new key (and the old one as
     `..._PREVIOUS_FILE`), run `kiln-server secrets rewrap`, which rewraps
     every DEK under the current KEK in small transactions (Vault: Transit
     `rewrap`, so the DEK never leaves Vault). It reports how many DEKs
     remain on other key IDs and exits non-zero until none do; only then
     is it safe to remove the previous key (or, for Vault, to raise
     `min_decryption_version`). The startup check in §2 catches a key
     removed too early. No secret value is re-encrypted, and the server
     keeps serving.
   - *DEK rotation:* `kiln-server secrets rotate-dek --org <slug>` creates a
     new active DEK version and re-encrypts that org's values under it;
     old versions are deleted once no value uses them. Other replicas may
     keep an old DEK in their cache for up to 5 minutes; that is harmless
     for routine rotation and is covered by the runbook below.
   - *KEK compromise (runbook):* rewrapping alone does not help, because
     an attacker with the old KEK and any database backup can still unwrap
     the old DEKs. The runbook is: rewrap under a new KEK, `rotate-dek` for
     every org, restart or wait out the DEK cache, and rotate the
     underlying credentials themselves, since their plaintext may already
     be known.
   - Every command is audit-logged.

## Consequences

- New package `internal/secrets` (crypto, providers, DEK cache), new service
  `internal/service/secrets`, tables `secret_data_keys` and `secrets`, a
  `secrets` field on steps in the pipeline spec, a `ref_protected` column on
  runs, and a `requires_trusted_runner` column on jobs used by the lease
  query.
- New permissions: `secrets:list` (developer; names are needed to write
  pipelines) and `secrets:manage` (admin).
- The scheduler gains a failure path at lease time (secret missing or not
  permitted).
- Operators must back up the master key separately from the database; losing
  it loses every secret. With Vault, a Vault outage fails every job that
  uses secrets (jobs without secrets are unaffected). The install docs say
  both.

## Security considerations (STRIDE)

**Data stores (T-44, T-47, T-62)**
- *Information disclosure:* a database or backup dump holds only ciphertext
  and wrapped DEKs; the KEK is in a file or in Vault. Values never appear in
  API responses, logs, traces, errors, or audit records.
- *Tampering (T-62):* GCM authenticates each value; the additional data
  binds it to org, scope kind and ID, name, DEK version, and value
  version, so rows cannot be swapped, moved between tenants, or rolled back
  to an older value. Wrapped DEKs are bound to their org (local: additional
  data; Vault: derived key context, verified at startup). Residual: an
  attacker with database write access can still delete secrets or
  re-insert a deleted secret together with its old DEK row.

**B2 lease delivery (T-12, T-13, T-15)**
- *Spoofing / elevation:* only trusted, unrevoked runners of the job's org
  receive secrets, checked in the lease query and again when building the
  lease; untrusted runs never resolve secrets at all.
- *Information disclosure:* mTLS 1.3 only; each lease carries only the
  secrets its steps declared, placed in those steps' environments.
- *Repudiation:* delivery is audited by secret name and value version.

**B3 job sandbox (T-18, T-25, T-27)**
- *Elevation (push access → deploy credentials):* secrets require a push to
  a VCS-protected branch unless an admin explicitly widens a secret; branch
  names alone never qualify.
- *Information disclosure:* fork and other untrusted runs get no secrets and
  never run on trusted runners. Other steps and plugins in a job do not get
  a step's secrets. Masking is a safety net for accidental printing by
  trusted code, not a boundary: a step can always exfiltrate what it was
  given, which is why delivery is opt-in per step and restricted to
  protected branches.

**B6 Vault (T-40, T-63)**
- The Vault address, token file, and CA bundle are admin configuration.
  Vault gets a dedicated client with its own allowlist and no redirects, so
  the token and DEKs cannot be redirected elsewhere and the global egress
  allowlist stays narrow. The token is never logged; errors carry status
  codes, never bodies.

**Key material (T-64):** the master key is read from a file (environment
only for embedded and development), derived into subkeys, and held in
memory; plaintext DEKs are cached for at most 5 minutes and wiped on
eviction where Go allows. Process memory and crash dumps of kiln-server
remain sensitive (residual).

**Repudiation (T-11):** every secret mutation, every delivery, and every
rotation is in the hash-chained audit log.
