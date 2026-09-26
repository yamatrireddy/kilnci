<!-- SPDX-License-Identifier: Apache-2.0 -->
# Kiln

Kiln is an open-source, self-hostable CI/CD platform: pipelines, GitOps delivery,
and container-based plugins, with web, desktop, and mobile clients over one API.
Kiln runs untrusted code next to production credentials, so security comes first;
see [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

**Status:** Phase 1 (CI core) is in progress; see the [roadmap](docs/roadmap.md)
for the per-slice table.

- **Phase 0 (foundations), done:** the Go control plane with OIDC sign-in, RBAC,
  audit log, and API tokens; the web app (React + Tailwind CSS); and the Tauri
  desktop app.
- **Phase 1 (CI core), done so far:** pipeline spec and safe YAML loader, DAG
  planning and state transitions, runs and jobs APIs, the scheduler with leases,
  the mTLS pull-only runner protocol, the hardened Docker executor with runner-side
  secret masking, log storage and live tails over SSE, the `kiln-runner` agent,
  the GitHub App with webhook triggers and commit statuses, the Phase 1
  security review, and the runs UI with the sanitizing log viewer.
- **Phase 1, not started:** the `kiln lint` CLI.
- **Next:** Phase 2 (secrets and trust), then GitOps, plugins and mobile, and
  1.0 hardening.

- Develop: [docs/development.md](docs/development.md)
- API: [docs/api/openapi.yaml](docs/api/openapi.yaml)
- Decisions: [docs/adr/](docs/adr/)
- Standards: [coding](docs/engineering/coding-standards.md), [security](docs/engineering/security-standards.md)

License: see [LICENSE](LICENSE). (The coding standards specify Apache-2.0 and every
source file carries `SPDX-License-Identifier: Apache-2.0`; the LICENSE file currently
contains the GPL-3.0 text. The maintainers need to reconcile the two.)
