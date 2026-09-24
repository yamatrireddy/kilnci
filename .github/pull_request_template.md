<!-- SPDX-License-Identifier: Apache-2.0 -->
## What and why

<!-- One logical change. Link the issue, ADR, or spec. -->

## How it was tested

<!-- Commands run, new tests (including negative and authorization tests). -->

## Security checklist

Tick each item or explain why it does not apply (security-standards §16).

- [ ] Authorization checked against the specific resource; cross-org test added
- [ ] Input validated (OpenAPI + business rules); size limits respected
- [ ] No string-built SQL, shell strings, or unchecked paths
- [ ] Outbound HTTP uses `platform/httpclient`
- [ ] No secrets or PII in logs, errors, traces, or fixtures
- [ ] Audit event added for privileged mutations
- [ ] New dependencies justified and license-checked
- [ ] Threat model / ADR updated if a trust boundary changed
- [ ] `make security` passes with no new findings

**Security-relevant areas touched:** <!-- list, or "none" -->
