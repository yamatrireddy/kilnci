<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-09-23

## Context

Kiln is security-critical and will have many contributors over time. Decisions that
change an invariant in `CLAUDE.md`, add a service, or move a trust boundary need a
durable record of why they were made and what risks were accepted.

## Decision

We keep Architecture Decision Records in `docs/adr/`, numbered sequentially
(`NNNN-kebab-title.md`). Each ADR has these sections:

1. **Context** — the forces at play.
2. **Decision** — what we will do.
3. **Consequences** — what becomes easier or harder.
4. **Security considerations** — STRIDE for each trust boundary touched (see
   `docs/threat-model.md`), or "No trust boundary is affected" with a reason.

ADRs are immutable once accepted; a later ADR supersedes an earlier one and both
link to each other.

## Consequences

- Reviewers can reject changes to invariants that arrive without an ADR.
- `docs/threat-model.md` is updated in the same PR as any ADR that moves a boundary.

## Security considerations

Process-only; no trust boundary is affected. It strengthens the SDL "Design" step
in security-standards §2.
