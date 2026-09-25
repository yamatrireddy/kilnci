<!-- SPDX-License-Identifier: Apache-2.0 -->
# Pipeline specification (version 1)

A pipeline lives in the repository at `.kiln/pipeline.yaml`. It is parsed only
by `server/internal/engine/spec` (the safe loader), both when a run is created
and by `POST /api/v1/pipelines/lint` (`kiln lint`). This document is the
contract; the parser, its fixtures in `server/internal/engine/spec/testdata/`,
and this file change together.

## Example

```yaml
version: 1
on:
  push:
    branches: [main, "release/*"]
  pull_request:
    branches: [main]
env:
  GOFLAGS: -mod=readonly
jobs:
  lint:
    image: golangci/golangci-lint:v2.4
    steps:
      - run: golangci-lint run ./...
  test:
    image: golang:1.27
    runs-on: [linux]
    needs: [lint]
    timeout: 20m
    steps:
      - name: Unit tests
        run: go test ./...
```

## Top level

| Field | Required | Type | Rules |
|---|---|---|---|
| `version` | yes | integer | Must be `1`. |
| `on` | no | mapping | Trigger filters, see below. Omitted: every push and every pull request. |
| `env` | no | mapping | Environment for every job (see *Environment*). |
| `jobs` | yes | mapping | 1–50 jobs, keyed by job ID. |

## `on`

| Field | Type | Rules |
|---|---|---|
| `push.branches` | list of globs | Branches whose pushes start a run. Omitted `push`: no push runs when `on` is present. |
| `pull_request.branches` | list of globs | **Base** branches of pull requests that start a run. |

Globs: `*` matches any characters except `/`; `**` matches any characters.
At most 50 patterns per list, each 1–255 characters. Tag pushes do not start
runs in version 1. A developer can always start a run manually.

## Jobs

Job IDs match `^[a-z][a-z0-9_-]{0,62}$`.

| Field | Required | Type | Rules |
|---|---|---|---|
| `image` | yes | string | Container image reference (`name[:tag][@digest]`), at most 255 characters. Every step runs in this image. |
| `runs-on` | no | list of strings | Runner labels the job requires (all must match). Each matches `^[a-z0-9][a-z0-9._-]{0,62}$`; at most 10. |
| `needs` | no | list of job IDs | Jobs that must succeed first. Unknown IDs and cycles are errors. |
| `timeout` | no | duration | Go duration (`90s`, `20m`, `2h`), 1 minute to 24 hours. Default `60m`. |
| `retries` | no | integer | 0–3. Retries after infrastructure failures (lost runner lease) only, never after a failing step. Default `0`. |
| `env` | no | mapping | Job environment; overrides pipeline `env`. |
| `steps` | yes | list | 1–100 steps. |

If a job fails, every job that needs it (directly or transitively) is
skipped. A run succeeds when all jobs succeed.

## Steps

| Field | Required | Type | Rules |
|---|---|---|---|
| `name` | no | string | 1–100 characters, no control characters. Default: the first line of `run`. |
| `run` | yes | string | Script executed with `/bin/sh -e -c` inside the job container, at most 64 KiB. |
| `env` | no | mapping | Step environment; overrides job `env`. |
| `timeout` | no | duration | 1 second to the job timeout. |

Steps run in order in the same container and workspace (`/workspace`, the
repository checked out at the run's commit). A failing step fails the job and
the remaining steps do not run.

## Environment

Keys match `^[A-Za-z_][A-Za-z0-9_]{0,127}$` and must not start with `KILN_`
(reserved). Values are scalars, at most 32 KiB each; at most 100 entries per
mapping. Kiln sets these variables for every step; they are untrusted data
and are never interpolated into scripts by Kiln:

`KILN_RUN_ID`, `KILN_JOB_ID`, `KILN_COMMIT_SHA`, `KILN_REF`, `KILN_BRANCH`,
`KILN_EVENT` (`push`, `pull_request`, or `manual`), `KILN_PR_NUMBER`,
`KILN_IS_FORK` (`true`/`false`), `CI=true`.

## Expressions

Version 1 has **no expression language**. Any string containing `${{` is
rejected so that a future expression engine cannot change the meaning of an
existing pipeline, and so that event data cannot be spliced into scripts
(threat T-24). Use the `KILN_*` environment variables instead, quoted:
`echo "$KILN_BRANCH"`.

## Safe-loader limits (threat T-07)

| Limit | Value |
|---|---|
| Document size | 256 KiB |
| Documents per file | 1 |
| Nesting depth | 20 |
| YAML nodes | 20 000 |
| Anchors, aliases, merge keys (`<<`) | rejected |
| Tags other than the core schema's | rejected |
| Duplicate mapping keys | rejected |
| Unknown fields | rejected |

Errors name the field path and line (for example
`jobs.test.timeout (line 12): must be between 1m and 24h`) and never echo
field values.
