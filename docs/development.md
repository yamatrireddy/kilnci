<!-- SPDX-License-Identifier: Apache-2.0 -->
# Developing Kiln

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Go | 1.27+ | Dev tools are pinned in `tools/go.mod` and run with `go tool`; no global installs |
| Node.js | 24.x (≥ 22.12) | |
| pnpm | 10.34+ | `corepack enable pnpm` or `npm i -g pnpm@10` |
| Docker | recent | Dev stack, integration tests (testcontainers), Semgrep and Trivy images |
| make, bash | | On Windows use Git Bash |
| Rust | stable (1.85+) | Desktop app only; on Linux also the WebKitGTK dev packages (see `ci.yml`) |

## Run it

```bash
pnpm install
make infra-up        # PostgreSQL + Dex (dev OIDC provider, no passwords)
make dev             # builds the web app and serves it from kiln-server on http://localhost:8080
```

Sign in with **Continue with single sign-on**. Dex's mock connector signs you in as
`kilgore@kilgore.trout`, which `scripts/dev-server.sh` lists as a bootstrap instance
admin, so you can create organizations. `make dev` serves the production build with
the production CSP; for UI hot reload run `pnpm --filter web dev` (port 5173, proxies
`/api`) and start the server with `KILN_PUBLIC_URL=http://localhost:5173 make dev`.
To connect a local runner, see the README's "Run it locally" section.

Desktop: `pnpm --filter desktop tauri dev`, then enter `http://localhost:8080` as the
server URL.

## Checks (the Definition of Done)

```bash
make generate   # sqlc, OpenAPI Go types + embedded spec, TS client
make lint       # golangci-lint (with depguard layering), eslint + tsc, actionlint
make test       # Go unit tests + Vitest
make test-integration   # Go integration tests (Docker, or KILN_TEST_DATABASE_URL)
make coverage   # includes integration tests; enforces 80% overall / 85% for auth
make security   # gitleaks, gosec, govulncheck, osv-scanner, pnpm audit, semgrep, trivy, licenses
make lint-rust  # clippy for the desktop shell
```

## Where things are

- Server layering and rules: `docs/engineering/coding-standards.md` §1 (enforced by
  `depguard` in `.golangci.yml`).
- Every HTTP route is declared in `server/internal/api/server.go` with the permission
  from `docs/api/openapi.yaml`; `TestRoutesMatchSpec` and `TestAuthzMatrix` keep the
  two and the authorization policy in sync.
- UI screens live in `packages/ui`; `apps/web` and `apps/desktop` only provide a
  `Platform` (API client, sign-in). Style with Tailwind classes and the
  primitives in `packages/ui/src/components/ui`; theme tokens live in
  `packages/ui/src/styles.css`. Nothing may inject `<style>` at runtime
  (ADR-0004); a test and ESLint enforce it.
