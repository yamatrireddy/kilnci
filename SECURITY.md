# Security Policy

Kiln executes build code and holds deployment credentials, so we take security
reports seriously and appreciate responsible disclosure.

## Supported versions

| Version | Supported |
|---|---|
| Latest minor release | Yes |
| Previous minor release | Security fixes only |
| Older | No |

## Reporting a vulnerability

**Please do not open public issues, discussions, or pull requests for security problems.**

Report privately through either:
- GitHub: the **Report a vulnerability** button under this repository's Security tab
- Email: security@<your-domain> (PGP key: `<key fingerprint and link>`)

Include affected version(s), configuration, reproduction steps or proof of concept,
and the impact you believe it has.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment and severity | within 7 days |
| Fix released — Critical | within 7 days of confirmation |
| Fix released — High | within 30 days |
| Fix released — Medium/Low | within 90 days / next release |

We will keep you updated, coordinate a disclosure date with you, request a CVE for
confirmed issues, and credit you in the advisory unless you prefer otherwise.

## Scope

In scope: the Kiln server, runner, CLI, web/desktop/mobile apps, official Helm chart,
official container images, and release artifacts.

Out of scope: vulnerabilities in third-party dependencies with no demonstrated impact
on Kiln, denial of service via volumetric traffic, social engineering, and findings
that require a compromised administrator account or host.

## Safe harbor

Good-faith research that follows this policy, avoids privacy violations and data
destruction, and does not degrade service for others will not be pursued legally by
the maintainers. Only test against your own installations.

## Verifying releases

All release artifacts and container images are signed with Sigstore cosign and ship
with an SBOM and SLSA provenance. See `docs/install/verify.md` for verification steps.
