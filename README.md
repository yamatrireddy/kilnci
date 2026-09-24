<!-- SPDX-License-Identifier: Apache-2.0 -->
# Kiln

Kiln is an open-source, self-hostable CI/CD platform: pipelines, GitOps delivery,
and container-based plugins, with web, desktop, and mobile clients over one API.
Kiln runs untrusted code next to production credentials, so security comes first;
see [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

**Status:** Phase 0 (foundations) is in place: the Go control plane with OIDC
sign-in, RBAC, audit log, and API tokens; the Mantine web app; and the Tauri
desktop app. Pipelines arrive in Phase 1 ([roadmap](docs/roadmap.md)).

- Develop: [docs/development.md](docs/development.md)
- API: [docs/api/openapi.yaml](docs/api/openapi.yaml)
- Decisions: [docs/adr/](docs/adr/)
- Standards: [coding](docs/engineering/coding-standards.md), [security](docs/engineering/security-standards.md)

License: see [LICENSE](LICENSE). (The coding standards specify Apache-2.0 and every
source file carries `SPDX-License-Identifier: Apache-2.0`; the LICENSE file currently
contains the GPL-3.0 text. The maintainers need to reconcile the two.)
