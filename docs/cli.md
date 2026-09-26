<!-- SPDX-License-Identifier: Apache-2.0 -->
# The `kiln` CLI

`kiln` is the command-line client for a Kiln server. Phase 1 ships one
command, `kiln lint`.

## Build

```bash
go build -C cli -o ../bin/kiln ./cmd/kiln
```

## `kiln lint`

Validates a pipeline without running it. The CLI sends the file to
`POST /api/v1/pipelines/lint`, so it applies exactly the rules the server
applies when it creates a run (ADR-0008, [pipeline spec](specs/pipeline.md));
there is no second parser to drift out of sync.

```bash
export KILN_SERVER=https://kiln.example.com
export KILN_TOKEN=kiln_pat_…        # an API token with the pipelines:lint scope
kiln lint                          # lints .kiln/pipeline.yaml
kiln lint path/to/pipeline.yaml
cat pipeline.yaml | kiln lint -    # from stdin
kiln lint --format json            # machine-readable output
```

| Flag | Default | Meaning |
|---|---|---|
| `--server URL` | `$KILN_SERVER` | Server base URL. Must be `https`; `http` is accepted only for `localhost` and loopback addresses. |
| `--token-file FILE\|-` | `$KILN_TOKEN` | File holding the token, or `-` for piped stdin (a terminal is refused, since it would echo the token). |
| `--format text\|json` | `text` | Output format. |

Text output is one problem per line, `FILE:LINE: PATH: MESSAGE`, which editors
and CI log annotators recognize.

**Exit status:** `0` the pipeline is valid, `1` it is invalid, `2` a usage,
file, network, or server error.

### Security properties

- The token is never accepted as a command-line argument (arguments are
  visible to other local users and end up in shell history), never printed,
  and never included in error messages.
- The token is sent only to the configured server: redirects are not
  followed, and it is never sent over plain http except to loopback.
- TLS certificates are always verified (TLS 1.2 minimum). Every request has a
  30-second timeout, and responses are capped at 1 MiB.
- Pipelines larger than the server's 256 KiB limit or not valid UTF-8 are
  rejected locally before anything is sent.
- Problem messages come from the server and can quote a pipeline from an
  untrusted pull request, so text output replaces terminal control characters
  (C0, DEL, and C1, which covers ANSI escape sequences) and line separators,
  and drops Unicode format characters (bidirectional overrides, zero-width
  characters). JSON output writes all of those as `\uXXXX` escapes, which
  decode back to the original text.
- The CLI talks only to the server the user names, so it builds its own HTTP
  client rather than using the server's SSRF-guarded `platform/httpclient`.

### In CI

Create an API token scoped to `pipelines:lint` only, store it in your CI's
secret store, and expose it as `KILN_TOKEN`. Lint reads no tenant data, so a
token with just this scope cannot read or change anything else.
