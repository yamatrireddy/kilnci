# Kiln Security Standards

Kiln runs arbitrary code from repositories, stores secrets, and holds credentials that
can deploy to production clusters. A vulnerability in Kiln can become a supply-chain
compromise for every organization that uses it. These standards define how we reduce
that risk through secure design, secure coding, automated gates, and review.

No process guarantees zero vulnerabilities. The goal is defense in depth: several
independent controls, so that one mistake does not become a breach, plus fast
detection and response when something slips through.

**Target:** OWASP ASVS v4 Level 2 for the server and web app; SLSA Build Level 3 for
release artifacts; CIS Kubernetes guidance for the Helm chart defaults.

---

## 1. Threat model summary

Full model: `docs/threat-model.md` (update it whenever a trust boundary changes).

**Assets:** secrets, VCS tokens, cluster credentials, signing keys, source code,
build artifacts, audit logs, user identities.

**Trust boundaries:**
1. Internet → API and webhook ingest
2. Server → runner (runners may be on untrusted hosts)
3. Runner → job container (job code is untrusted)
4. Server → target Kubernetes clusters (GitOps)
5. Clients (web, desktop, mobile) → API
6. Server → third parties (VCS, IdP, Vault, notification targets)

**Attackers to design for:**
- Malicious pull request author (especially from forks)
- Compromised or malicious runner host
- Authenticated user trying to reach another org's data (IDOR, privilege escalation)
- Attacker controlling a webhook payload, a repo's pipeline YAML, or manifests
- Supply-chain attacker via dependencies, base images, or CI actions
- Network attacker between any two components

## 2. Secure development lifecycle

1. **Design:** features that cross a trust boundary need an ADR with a
   "Security considerations" section (STRIDE per boundary touched).
2. **Implement:** follow this document; use the platform helpers listed here rather
   than writing new security-sensitive code.
3. **Verify:** automated gates (section 13) plus the security-reviewer subagent and
   human security review for sensitive paths.
4. **Release:** signed artifacts, SBOM, provenance.
5. **Respond:** disclosure policy in `SECURITY.md`; fix SLAs in section 14.

## 3. Authentication

- Users authenticate via OIDC (Authorization Code + PKCE). Kiln does not store user
  passwords. MFA is delegated to the IdP; orgs can require an `amr` claim.
- Web sessions: server-side session IDs in cookies with `HttpOnly`, `Secure`,
  `SameSite=Lax`, `__Host-` prefix; 12-hour absolute and 1-hour idle timeouts;
  session ID rotated on login and privilege change.
- API tokens: 256-bit random from `crypto/rand`, shown once, stored as SHA-256 hash,
  prefixed (`kiln_pat_`) so secret scanners can detect leaks. Scoped, expiring
  (max 1 year), revocable, and last-used tracked.
- Desktop and mobile use OIDC with PKCE via the system browser (never an embedded
  webview login) and store refresh tokens in the OS keychain/keystore.
- Runner auth: single-use registration token → runner obtains an mTLS client
  certificate with short validity, auto-rotated.
- Rate limit and lock out on authentication failures per IP and per principal.

## 4. Authorization

- **Deny by default.** A route without an explicit permission declaration fails a
  startup check and a CI test.
- Permissions are checked in the service layer against the specific resource:
  `authz.Check(ctx, principal, "runs:cancel", project)`. Role alone is never enough.
- Every tenant-scoped query includes `org_id`; repository methods take it as a
  required argument.
- Cross-org access returns 404.
- An authorization matrix test (`internal/api/authz_matrix_test.go`) runs every
  endpoint against every role plus a foreign-org user and an unauthenticated caller.
- Privileged actions (secret changes, RBAC changes, production syncs, runner
  registration) are audit-logged and can require approval policies.
- Runners are principals with minimal permissions: lease jobs for their labels,
  stream logs for their leased jobs, report results. Nothing else.

## 5. Input handling

- All HTTP input is validated against OpenAPI by middleware before reaching handlers;
  services validate business rules again.
- Request body size limits (default 1 MiB; webhooks 5 MiB; uploads configured
  separately). Header and query length limits.
- **YAML (pipelines, manifests):** use the safe loader in `engine/spec` with limits on
  document size, nesting depth, node count, and alias expansion (prevents
  "billion laughs"). Unknown fields are errors.
- **Expressions** (`${{ }}` or `${VAR}` interpolation): evaluated by the sandboxed
  expression engine only; never passed to a shell or template engine. Values from
  event payloads (PR titles, branch names) are treated as untrusted data and passed
  to steps as environment variables, not interpolated into commands.
- **Paths:** use `platform/safepath.Join(root, userPath)`, which rejects absolute
  paths, `..` escapes, and symlinks that resolve outside the root.
- **Git refs and repo URLs:** validated against strict patterns; `git` is invoked with
  argument arrays and `--` separators to prevent option injection.

## 6. Injection prevention

| Class | Rule |
|---|---|
| SQL | sqlc only; no string concatenation; no dynamic ORDER BY except from allow-lists |
| OS command | `exec.CommandContext` with argument arrays; never `sh -c` with user data on the server |
| SSRF | all outbound HTTP via `platform/httpclient`, which resolves DNS, blocks private/loopback/link-local/metadata ranges (incl. `169.254.169.254`, `fd00:ec2::254`), re-checks after redirects, and limits redirects to 3 |
| XSS | React escaping only; no `dangerouslySetInnerHTML`; log viewer parses ANSI into safe spans; markdown rendered with a sanitizer allow-list |
| Log injection | newlines and control characters escaped in structured logs |
| Header injection | no user input in response headers except validated values |
| Deserialization | no `gob`/`encoding/xml` of untrusted input; JSON with `DisallowUnknownFields` for internal protocols |

## 7. Secrets management

- Envelope encryption: each secret encrypted with a per-org data key (AES-256-GCM);
  data keys encrypted by the master key from KMS, Vault Transit, or `KILN_MASTER_KEY`
  for single-node installs. Key rotation supported without downtime.
- Secrets are decrypted only when building a job lease for an authorized runner and
  are sent only over mTLS.
- The runner masks every secret value, its base64 and URL-encoded forms, and
  multi-line variants in streamed logs, before data leaves the runner.
- Secrets never appear in: logs, traces, metrics, error messages, API responses
  (write-only; reads return metadata only), URLs, or crash reports.
- Secrets are scoped (org, project, environment) and can be restricted to protected
  branches and specific pipelines.
- Fork PRs receive no secrets by default.
- Cluster credentials for GitOps are stored as secrets and use least-privilege
  service accounts per target namespace.

## 8. Runner and job isolation

Job code is hostile by assumption.

- Job containers run as a non-root user, with `no-new-privileges`, all capabilities
  dropped (add back only what a plugin declares and an admin allows), default
  seccomp and AppArmor profiles, and resource limits (CPU, memory, PIDs, disk).
- No `--privileged`, no host network, no host PID, no Docker socket mount by default.
  Docker-in-Docker builds use rootless BuildKit or a sidecar with explicit opt-in.
- Kubernetes executor: one pod per job in a dedicated namespace, Pod Security
  Standard `restricted`, NetworkPolicy denying access to the cluster API, the
  metadata service, and internal services unless allowed.
- Ephemeral runners are the recommended default (one job per runner, then destroy).
  Stronger isolation (gVisor, Kata, Firecracker) supported as runtime classes.
- Runners labeled `trusted` (with access to deploy credentials) never run fork PRs
  or jobs from unprotected branches.
- Workspaces are wiped between jobs; caches are scoped per project and branch
  protection level so untrusted branches cannot poison caches used by `main`.

## 9. GitOps / cluster access

- The GitOps controller runs with a Kubernetes service account scoped to the
  namespaces each Application targets; no cluster-admin by default.
- Applications declare allowed resource kinds and namespaces; rendered manifests that
  escape them are rejected before apply.
- Helm/Kustomize rendering runs in a sandboxed subprocess without network access to
  internal services, with time and memory limits.
- Production syncs can require approval and verified commit signatures.
- Every sync records who or what triggered it, the git revision, and the diff hash.

## 10. Web, desktop, and mobile clients

**Web**
- Security headers: strict CSP (`default-src 'self'`, no `unsafe-inline`/`unsafe-eval`,
  nonces for anything unavoidable), `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `frame-ancestors 'none'`, `Permissions-Policy` minimal.
- CSRF protection for cookie-authenticated state-changing requests (SameSite plus a
  synchronizer token).
- CORS: explicit origin allowlist, never `*` with credentials.
- WebSocket connections authenticate on upgrade and check `Origin`.

**Desktop (Tauri)**
- Capabilities grant only the specific commands and scopes needed; filesystem and
  shell access are scoped to the local runner's directory and binary.
- CSP enforced in the Tauri config; no remote content loaded into privileged windows.
- Auto-updater uses signed updates with the public key pinned in the app.
- The embedded local runner listens only on a local socket or loopback with a
  per-session token.

**Mobile (Expo)**
- Tokens in `expo-secure-store` (Keychain/Keystore); nothing sensitive in AsyncStorage.
- No secrets or API keys in the bundle.
- Deep links and push notification payloads are validated; they may navigate but
  never trigger actions without user confirmation.
- Deployment approvals require biometric or device-credential confirmation.
- Screens showing logs or secrets metadata are excluded from app-switcher snapshots.

## 11. Cryptography

- Only Go standard library and `golang.org/x/crypto`; Rust `ring`/`rustls` in desktop.
- TLS 1.2 minimum, TLS 1.3 preferred; modern cipher suites only; never set
  `InsecureSkipVerify` outside tests.
- `crypto/rand` for tokens, IDs used as secrets, and nonces.
- Constant-time comparison (`subtle.ConstantTimeCompare`, `hmac.Equal`) for tokens,
  signatures, and hashes.
- Webhook signatures verified before parsing the body.
- No MD5 or SHA-1 for security; no custom crypto or homegrown protocols.

## 12. Logging, audit, and abuse prevention

- Audit events are append-only, include actor, action, target, org, source IP,
  user agent, request ID, and result, and are exportable to SIEM (syslog/OTLP).
- Audit records are hash-chained so tampering is detectable.
- Rate limiting per principal and per IP on auth, API, webhooks, and log streaming.
- Quotas per org on concurrent runs, log volume, and artifact storage to limit
  resource-exhaustion attacks.

## 13. Supply-chain security

**Dependencies**
- Lockfiles committed (`go.sum`, `pnpm-lock.yaml`, `Cargo.lock`).
- License allowlist: Apache-2.0, MIT, BSD-2/3-Clause, ISC, MPL-2.0 (file-level).
  GPL/AGPL/SSPL and unknown licenses are rejected. Public-domain-equivalent
  licenses (0BSD, CC0-1.0, BlueOak-1.0.0, MIT-0) and named exceptions for
  development-only npm packages are listed in `scripts/license-check.mjs`;
  both lists need security-owner approval.
- New dependencies need: active maintenance, no known unpatched critical/high
  vulnerabilities, and a justification. Prefer the standard library.
- Renovate opens update PRs; security updates are prioritized.

**CI/CD of Kiln itself**
- GitHub Actions pinned to full commit SHAs; `permissions:` minimal per job
  (default `contents: read`).
- No secrets available to workflows triggered from forks; `pull_request_target`
  is forbidden unless reviewed by security owners.
- Branch protection: required reviews, required status checks, signed commits,
  no force pushes to `main`.

**Automated gates** (all run in CI; `make security` runs them locally)

| Tool | Checks | Blocks merge on |
|---|---|---|
| gosec | Go security anti-patterns | Medium and above |
| govulncheck | Reachable known vulns in Go deps | Any reachable vuln |
| Semgrep (custom Kiln rules + OWASP rulesets) | Injection, authz omissions, banned APIs | Error severity |
| CodeQL | Deep dataflow analysis (Go, TS) | High and above |
| gitleaks | Committed secrets | Any finding |
| osv-scanner | Known vulns across Go, npm, Cargo | High and above |
| pnpm audit / cargo audit | Ecosystem advisories | High and above |
| Trivy | Container image and IaC (Helm, Dockerfiles) misconfig + CVEs | High and above |
| hadolint, actionlint, kube-linter | Dockerfile, workflow, and manifest hygiene | Errors |
| Dependency license check | License allowlist | Any disallowed license |
| Go fuzzing (scheduled) | Parser, masker, path, webhook crashes | Any crash |

**Releases**
- Minimal base images (distroless or `scratch` for Go binaries), non-root user,
  read-only root filesystem.
- Reproducible builds; SBOM (SPDX and CycloneDX via Syft) attached to every release.
- Artifacts and images signed with Sigstore cosign (keyless, OIDC-bound) and
  SLSA provenance published. Install docs show how to verify signatures.
- DAST (OWASP ZAP baseline) against a staging deployment before each release.
- Third-party penetration test before 1.0 and annually after.

## 14. Vulnerability management

| Severity (CVSS v3.1/v4) | Fix and release target |
|---|---|
| Critical (9.0+) | 7 days |
| High (7.0–8.9) | 30 days |
| Medium (4.0–6.9) | 90 days |
| Low | Next scheduled release |

- Reports come in via GitHub private vulnerability reporting or the email in
  `SECURITY.md`; acknowledged within 3 business days.
- Fixes are developed in private security advisories; CVEs are requested for
  confirmed issues; advisories credit reporters who want credit.
- Each fixed vulnerability gets a regression test and, where possible, a new
  Semgrep rule so the same class is caught automatically.

## 15. Rules for AI-assisted development

- Claude and other assistants follow this document exactly like human contributors.
- Generated code touching the security-sensitive areas listed under Required reading in `CLAUDE.md`
  must be reviewed by the security-reviewer subagent and a human security owner.
- Never disable scanners, lint rules, TLS verification, or tests to make a change pass.
  Suppressions need an inline justification and security-owner approval.
- Do not add dependencies suggested only by memory without verifying the package name
  and publisher (typosquatting risk).
- Do not paste real secrets, customer data, or production logs into prompts or fixtures.

## 16. Pull request security checklist

Included in the PR template; authors tick each item or explain why it doesn't apply.

- [ ] Authorization checked against the specific resource; cross-org test added
- [ ] Input validated (OpenAPI + business rules); size limits respected
- [ ] No string-built SQL, shell strings, or unchecked paths
- [ ] Outbound HTTP uses `platform/httpclient`
- [ ] No secrets or PII in logs, errors, traces, or fixtures
- [ ] Audit event added for privileged mutations
- [ ] New dependencies justified and license-checked
- [ ] Threat model / ADR updated if a trust boundary changed
- [ ] `make security` passes with no new findings
