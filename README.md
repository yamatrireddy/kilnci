<!-- SPDX-License-Identifier: Apache-2.0 -->
# Kiln

Kiln is an open-source, self-hostable CI/CD platform: pipelines, GitOps delivery,
and container-based plugins, with web, desktop, and mobile clients over one API.
Kiln runs untrusted code next to production credentials, so security comes first;
see [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

## Status

**Phase 1 (CI core): every slice is implemented; the phase exit check (a push to a
linked GitHub repository runs end to end with live logs) has not been verified
yet.** The [roadmap](docs/roadmap.md) has the per-slice table and open follow-ups.

| Area | What exists today |
|---|---|
| Server (`server/`) | Go control plane: OIDC sign-in (no passwords), server-side sessions with CSRF, RBAC with per-resource checks, hash-chained audit log, personal API tokens, deny-by-default router, strict security headers and CSP |
| Organizations and projects | Create orgs (instance admins) and projects; add members and set roles (viewer, developer, admin, owner); view the org audit log |
| Pipelines | `.kiln/pipeline.yaml` [spec](docs/specs/pipeline.md), safe YAML loader, DAG planning, explicit state transitions, lint API |
| Runs | Runs and jobs APIs (list, read, cancel, approve), scheduler with leases and heartbeats, manual runs on a branch |
| Runners (`runner/`) | `kiln-runner` pulls jobs over mTLS (single-use registration tokens, 24 h certificates, revocation) and runs every step in a hardened Docker container, masking secrets before logs leave the host ([docs/runners.md](docs/runners.md)) |
| Logs | Chunks in filesystem or S3 storage, live tails over NATS (in-process in `--embedded`) streamed to the browser as Server-Sent Events |
| GitHub | GitHub App with signature-verified webhooks, push and pull-request triggers, fork detection with approval, commit statuses |
| Web app (`apps/web`) | React + Tailwind CSS: sign-in, organizations, projects, members, audit log, API tokens, runs list, run page, and a live log viewer that sanitizes ANSI output |
| Desktop app (`apps/desktop`) | Tauri 2 shell around the same UI, with tokens held in the OS keychain; logs refresh every 30 s instead of streaming |
| CLI (`cli/`) | [`kiln lint`](docs/cli.md) validates a pipeline against the server |

**Not yet:** secrets management and trusted-runner policy (Phase 2), GitOps
delivery (Phase 3), plugins, the Kubernetes executor, and the mobile app (Phase 4).
There is no UI yet for runners or for linking a repository; both are API only.

## Run it locally

### Prerequisites

Go 1.27+, Node.js 24 (22.12 or newer works), pnpm 10.34+, Docker (running), make,
and bash (Git Bash on Windows). Rust stable is needed only for the desktop app.
[docs/development.md](docs/development.md) lists exact versions.

### 1. Start the server and web app

```bash
pnpm install
make dev
```

`make dev` starts PostgreSQL and Dex (a development-only sign-in provider) in Docker,
builds the web app, and runs `kiln-server` in the foreground. The first run downloads
Go modules and images, so give it a minute. It is ready when the log shows
`http server listening` with `addr=127.0.0.1:8080`.

### 2. Sign in and look around

1. Open <http://localhost:8080> and choose **Continue with single sign-on**.
   Dex signs you in as `kilgore@kilgore.trout` with no password; that user is an
   instance admin in the dev setup.
2. **New organization**: create one (for example "Acme"). You become its owner.
3. In the organization, **New project** creates a project. The **Members** tab
   adds people and changes roles, and **Audit log** shows every change you made.
4. Open the project to see its runs list. It stays empty locally (see below).
5. **API tokens** (left sidebar) creates personal tokens for scripts and the CLI.

Runs are created by GitHub pushes and pull requests to a linked repository, so a
local setup without a GitHub App shows no runs. To try that flow you need your own
GitHub App and a public URL for its webhooks; the settings are the
`KILN_GITHUB_APP_*` variables in `server/internal/platform/config`.

### 3. Optional: connect a runner

The runner listener is off unless the server has a runner CA. Stop `make dev`
(Ctrl+C), then:

```bash
# Once: create a runner CA for local use (kept outside the repo)
go -C server run ./cmd/kiln-server runner-ca init --dir ~/.kiln-dev/runner-ca

# Start the server with the runner listener on loopback
KILN_RUNNER_CA_DIR=~/.kiln-dev/runner-ca KILN_RUNNER_HOSTNAMES=localhost \
  KILN_RUNNER_ADDR=127.0.0.1:9443 make dev
```

Create a registration token for your organization. There is no UI for this yet;
in the browser's developer console on <http://localhost:8080> (signed in), run:

```js
const s = await (await fetch("/api/v1/session")).json();
const r = await fetch("/api/v1/orgs/acme/runner-registration-tokens", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-CSRF-Token": s.csrfToken },
  body: JSON.stringify({ labels: ["linux", "amd64"], trusted: false, expiresInMinutes: 30 }),
});
console.log((await r.json()).token);
```

Save the printed token to a file (for example `~/.kiln-dev/token.txt`), then build,
register, and start the runner:

```bash
go -C runner build -o ../bin/kiln-runner ./cmd/kiln-runner
mkdir -m 700 -p ~/.kiln-dev/runner-state
bin/kiln-runner register --server localhost:9443 --ca-file ~/.kiln-dev/runner-ca/ca.crt \
  --token-file - --name dev-runner --state-dir ~/.kiln-dev/runner-state < ~/.kiln-dev/token.txt
rm ~/.kiln-dev/token.txt
bin/kiln-runner run --state-dir ~/.kiln-dev/runner-state --egress-policy none --job-disk-limit=off
```

`--egress-policy none` and `--job-disk-limit=off` skip host firewall and disk-quota
setup, which is fine for a laptop but not for a real runner host; see
[docs/runners.md](docs/runners.md). The runner then appears in
`GET /api/v1/orgs/acme/runners` and waits for jobs.

### 4. Optional: lint a pipeline with the CLI

Create an API token with only the `pipelines:lint` scope under **API tokens**, save
it to a file outside the repository (for example `~/.kiln-dev/lint-token.txt`), then:

```bash
go build -C cli -o ../bin/kiln ./cmd/kiln
bin/kiln lint --server http://localhost:8080 --token-file - \
  server/internal/engine/spec/testdata/valid/full.yaml < ~/.kiln-dev/lint-token.txt
```

It prints `pipeline is valid`, or one `FILE:LINE: PATH: MESSAGE` line per problem.

### 5. Optional: UI hot reload and the desktop app

- **Hot reload:** run `pnpm --filter web dev` (port 5173, proxies `/api` to the
  server) and start the server with `KILN_PUBLIC_URL=http://localhost:5173 make dev`.
  Then use <http://localhost:5173>.
- **Desktop:** with the server running, run `pnpm --filter desktop tauri dev` and
  enter `http://localhost:8080` as the server URL. On Linux this needs the WebKitGTK
  development packages (see `.github/workflows/ci.yml`).

### Stop and reset

Ctrl+C stops the server. `make infra-down` stops PostgreSQL and Dex; add
`docker volume rm kiln-dev_pgdata` to delete all local data and start fresh.

## Develop

- Checks and layout: [docs/development.md](docs/development.md)
- API: [docs/api/openapi.yaml](docs/api/openapi.yaml)
- Decisions: [docs/adr/](docs/adr/)
- Standards: [coding](docs/engineering/coding-standards.md), [security](docs/engineering/security-standards.md)

License: see [LICENSE](LICENSE). (The coding standards specify Apache-2.0 and every
source file carries `SPDX-License-Identifier: Apache-2.0`; the LICENSE file currently
contains the GPL-3.0 text. The maintainers need to reconcile the two.)
