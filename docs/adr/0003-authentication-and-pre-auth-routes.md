<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0003: Authentication flows and the pre-authentication route class

- **Status:** Accepted (approved by the maintainer, 2026-09-24)
- **Date:** 2026-09-24
- **Amends:** CLAUDE.md architecture invariant 9

## Context

Invariant 9 says every route is denied unless explicitly allowed, and that only
`/healthz`, `/readyz`, and signature-verified webhook ingest are unauthenticated.
Kiln has no password login (security-standards §3): users authenticate through
an OIDC IdP. An OIDC login necessarily has endpoints that run *before* a
principal exists: the login start (redirect to the IdP), the redirect target,
and, for the desktop app, a token endpoint that redeems a one-time code.

The desktop app must bundle its UI locally (no remote content in privileged
windows, SS §10), so it calls the API cross-origin and cannot rely on
`SameSite` browser cookies. It needs bearer credentials obtained through the
system browser with PKCE (SS §3, RFC 8252).

The built web app's static files (HTML, JS, CSS) must also load before sign-in.

## Decision

1. **A third route class, `preauth`,** joins `public` and authenticated routes.
   The router only accepts it for exactly these operations, enforced at
   startup (`internal/api/router.go`):
   - `GET /api/v1/auth/login`
   - `GET /api/v1/auth/callback`
   - `POST /api/v1/auth/token`

   These handlers establish identity; they never read or change tenant data.
   Static SPA assets are served outside the API router and contain no data.

2. **Web sign-in** is OIDC Authorization Code + PKCE with Kiln as a
   confidential (or public, PKCE-only) client:
   - `login` stores a server-side login state (hash of a 256-bit `state`,
     `nonce`, PKCE verifier, 10-minute expiry) and binds it to the browser with
     an HttpOnly `__Host-kiln_login` cookie, so a login started by an attacker
     cannot be completed in a victim's browser (login CSRF).
   - `callback` requires the cookie to match `state` (constant time), consumes
     the state exactly once, exchanges the code with the PKCE verifier,
     verifies the ID token (`iss`, `aud`, `exp`, signature via go-oidc), checks
     `nonce` (constant time), requires `email_verified`, and optionally requires
     an `amr` value (e.g. `mfa`).
   - The session cookie `__Host-kiln_session` (HttpOnly, Secure, SameSite=Lax,
     Path=/) holds a 256-bit random secret; only its SHA-256 is stored.
     Absolute timeout 12h, idle timeout 1h. A new session ID is issued at every
     login (fixation-safe).
   - CSRF: unsafe requests with a session cookie must send `X-CSRF-Token`,
     which is HMAC-SHA256(session secret, "kiln-csrf-v1"). It is derivable only
     by someone who holds the HttpOnly cookie, is returned by
     `GET /api/v1/session`, and is checked in constant time. A mismatching
     `Origin` header is also rejected.

3. **Desktop sign-in is brokered by Kiln** (maintainer decision):
   - The app starts a loopback listener on `127.0.0.1:<port>`, creates its own
     PKCE pair and `state`, and opens the system browser at
     `login?client=desktop&redirectUri=http://127.0.0.1:<port>/callback&codeChallenge=...&state=...`.
   - After the web-style IdP flow (same cookie binding), Kiln redirects to the
     loopback URI with a one-time code (256-bit, 60 s, single use, bound to the
     code challenge and redirect URI).
   - `POST /auth/token` (`authorization_code`) verifies the PKCE verifier and
     issues an opaque access token (`kiln_at_`, 15 min) and a rotating refresh
     token (`kiln_rt_`, 30 days sliding, 90 days absolute per grant). Only
     hashes are stored. Reusing a rotated refresh token revokes the whole
     grant (token family) and is audited.
   - The app keeps the refresh token in the OS keychain and the access token in
     Rust memory only, bound to the issuing server's origin; the webview never
     receives either and reaches the API only through a Rust command that
     allows `/api/v1/*` (auth routes excluded) after URL normalization.
   - Desktop logins send `prompt=login` so the IdP re-authenticates the user.
     This is advisory; verifying `auth_time` (with `max_age=0`) is a Phase 1
     follow-up recorded in the threat model.

4. **Personal API tokens** (`kiln_pat_` + 256 bits) are created from a
   session only (an API token cannot mint tokens), shown once, stored as
   SHA-256, scoped to an allow-list of read-only actions in Phase 0, expire in
   at most 365 days, are capped at 50 active per user, and are revocable.

5. **Account provisioning is closed by default.** A first sign-in succeeds
   only if the verified email is a bootstrap admin, matches a pending invite
   created by an org admin, or auto-provisioning is explicitly enabled
   (optionally restricted to email domains).

6. **Rate limits:** per-IP limits on all API routes, stricter limits on
   `/api/v1/auth/*`, and a per-IP authentication-failure budget that returns
   429 before credentials are even checked.

## Consequences

- Invariant 9 in CLAUDE.md is updated to name the pre-auth routes and cite
  this ADR. Adding any route to the `preauth` or `public` allow-lists requires
  a new ADR.
- The server now stores credential hashes and login state; the threat model's
  B1 and B5 entries (T-02, T-03, T-34, T-41) move from P to I.
- The desktop app must implement the loopback listener and keychain storage
  (slice 6).

## Security considerations (STRIDE)

**B1 Internet → control plane (pre-auth routes)**
- *Spoofing:* forged callbacks fail without the matching `__Host-` login
  cookie and a single-use server-side state; ID tokens are signature-,
  issuer-, audience-, expiry-, and nonce-checked. Desktop codes require the
  PKCE verifier.
- *Tampering:* `returnTo` accepts only same-origin paths (no scheme, no `//`,
  no backslash), preventing open redirects; desktop redirect URIs are limited
  to `http://127.0.0.1:<port>/callback`.
- *Repudiation:* sign-ins, token issuance, refresh-token reuse, and token
  creation/revocation are audit-logged.
- *Information disclosure:* codes, states, and tokens never appear in logs
  (the access log records route patterns, not URLs); errors are generic.
- *Denial of service:* rate limits and failure budgets; login states expire in
  10 minutes and are garbage-collected.
- *Elevation of privilege:* pre-auth handlers cannot reach tenant data; the
  router rejects any other route declared `preauth`.

**B5 Clients → API**
- Session theft is limited by HttpOnly/Secure/`__Host-` cookies, idle and
  absolute timeouts, and revocation on sign-out. Desktop refresh tokens live in
  the OS keychain; reuse detection revokes a stolen family. CSRF is blocked by
  the synchronizer token plus Origin check; CORS never allows credentials.

**B6 Control plane → IdP**
- Discovery, JWKS, and token requests go through `platform/httpclient` (SSRF
  protection; a private IdP must be allow-listed with
  `KILN_EGRESS_ALLOWED_PREFIXES`). The issuer must be https outside development.
