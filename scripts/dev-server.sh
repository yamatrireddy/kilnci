#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs kiln-server against the dev compose stack (`make infra-up`), serving the
# built web app (`pnpm --filter web build`) exactly as production does, with the
# strict CSP. Development-only settings; never use these values elsewhere.
set -euo pipefail
cd "$(dirname "$0")/../server"
# Toolchain locations for Windows Git Bash; harmless elsewhere.
export PATH="/c/Program Files/Go/bin:$HOME/go/bin:$PATH"

export KILN_ENV=development
export KILN_TLS_MODE=upstream
export KILN_HTTP_ADDR=127.0.0.1:8080
export KILN_PUBLIC_URL="${KILN_PUBLIC_URL:-http://localhost:8080}"
export KILN_DB_URL="postgres://kiln:kiln-dev-only@localhost:5432/kiln?sslmode=disable" # gitleaks:allow (dev-only, loopback)
export KILN_OIDC_ISSUER_URL=http://localhost:5556/dex
export KILN_OIDC_CLIENT_ID=kiln-dev
export KILN_EGRESS_ALLOWED_PREFIXES=127.0.0.1/32,::1/128
export KILN_AUTH_BOOTSTRAP_ADMIN_EMAILS=kilgore@kilgore.trout
export KILN_CORS_ALLOWED_ORIGINS=tauri://localhost,http://tauri.localhost
export KILN_WEB_DIR=../apps/web/dist
export KILN_LOG_LEVEL="${KILN_LOG_LEVEL:-info}"

exec go run ./cmd/kiln-server "$@"
