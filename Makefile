# SPDX-License-Identifier: Apache-2.0
#
# Developer entry points. Every target here is also what CI runs, so a green
# `make generate lint test security` locally should mean a green PR.
#
# Dev tools are pinned in tools/go.mod (Go `tool` directives) and run with
# `go tool`, so no global installs are needed beyond Go, Node/pnpm, and Docker.
# tools/ is deliberately outside go.work so its large dependency graph never
# influences the versions the server builds with.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO_MODULES   := ./server/...
# $(call tool,NAME) expands to the path of the pinned, cached tool binary, so
# tools run from any directory with the caller's working directory intact.
tool          = "$(shell GOWORK=off go -C $(CURDIR)/tools tool -n $(1))"
ACTIONLINT   := GOWORK=off go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
COMPOSE      := docker compose -f deploy/compose/compose.dev.yaml
SEMGREP_IMG  := semgrep/semgrep:1.177.0@sha256:d1825c2c72110b5bfbf0602ff68f7f117322597a7c33037a79dba9f897f5f1f0
TRIVY_IMG    := aquasec/trivy:0.74.0@sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9
MIGRATIONS   := server/migrations
# MSYS_NO_PATHCONV stops Git Bash on Windows rewriting container paths like /src.
DOCKER_RUN   := MSYS_NO_PATHCONV=1 docker run --rm
# -race needs cgo. CI (Linux) always has it; Windows dev boxes without a C
# compiler report CGO_ENABLED=0 and fall back to plain tests.
RACE         ?= $(if $(filter 1,$(shell go env CGO_ENABLED)),-race,)

# Coverage floors (docs/engineering/coding-standards.md §10).
COVER_FLOOR          := 80
COVER_CRITICAL_FLOOR := 85
COVER_CRITICAL_PKGS  := internal/auth internal/auth/authz

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

## ---------------------------------------------------------------- dev stack

.PHONY: dev
dev: infra-up ## Build the web app and run the server against the dev stack (http://localhost:8080)
	pnpm --filter web build
	bash scripts/dev-server.sh

.PHONY: infra-up
infra-up: ## Start PostgreSQL for local development
	$(COMPOSE) up -d --wait

.PHONY: infra-down
infra-down: ## Stop local infrastructure
	$(COMPOSE) down

## ----------------------------------------------------------------- codegen

.PHONY: generate
generate: generate-sql generate-proto generate-openapi ## Regenerate all generated code (sqlc, protobuf, OpenAPI Go + TS)

.PHONY: generate-sql
generate-sql:
	cd server && $(call tool,sqlc) generate
	bash scripts/spdx-prepend.sh // server/internal/store/db/*.go

.PHONY: generate-proto
generate-proto:
	cd proto && GOWORK=off $(call tool,buf) lint
	cd proto && GOWORK=off $(call tool,buf) generate

.PHONY: generate-openapi
generate-openapi:
	cd server && $(call tool,oapi-codegen) -config internal/api/gen/oapi-codegen.yaml ../docs/api/openapi.yaml
	bash scripts/spdx-prepend.sh // server/internal/api/gen/types_gen.go
	cp docs/api/openapi.yaml server/internal/api/gen/openapi.yaml
	pnpm --filter @kiln/api-client generate

.PHONY: migration
migration: ## Create a migration: make migration name=add_runs_table
	@test -n "$(name)" || (echo "usage: make migration name=<snake_case_name>" && exit 1)
	$(call tool,goose) -dir $(MIGRATIONS) -s create $(name) sql

## -------------------------------------------------------------------- test

.PHONY: test
test: test-go test-ts ## Run all unit tests

.PHONY: test-go
test-go:
	cd server && go test $(RACE) -count=1 ./...
	cd runner && go test $(RACE) -count=1 ./...

.PHONY: test-ts
test-ts:
	pnpm -r --if-present test

.PHONY: test-integration
test-integration: ## Integration tests (needs Docker; uses testcontainers)
	cd server && go test $(RACE) -count=1 -tags=integration ./...
	cd runner && go test $(RACE) -count=1 -tags=integration ./...

.PHONY: e2e
e2e: ## End-to-end tests against the compose stack
	@echo "e2e: no suites yet in Phase 0 (see docs/roadmap.md)"

.PHONY: coverage
coverage: ## Coverage report with floors enforced
	# Integration tests included; -coverpkg credits cross-package tests (the
	# API authz matrix exercises auth and services). Generated code is excluded.
	cd server && go test -count=1 -tags=integration -coverpkg=./... -coverprofile=coverage.raw ./...
	cd server && grep -v -E '/(store/db|api/gen|auth/authtest|store/storetest)/|/cmd/' coverage.raw > coverage.out
	cd server && go tool cover -func=coverage.out | tail -1
	cd server && bash ../scripts/coverage-check.sh coverage.out $(COVER_FLOOR) $(COVER_CRITICAL_FLOOR) $(COVER_CRITICAL_PKGS)
	pnpm -r --if-present coverage

## -------------------------------------------------------------------- lint

.PHONY: lint
lint: lint-go lint-ts lint-workflows ## golangci-lint, eslint + tsc, actionlint (hadolint/clippy when those parts exist)

.PHONY: lint-go
lint-go:
	cd server && $(call tool,golangci-lint) run --config ../.golangci.yml ./...
	cd runner && $(call tool,golangci-lint) run --config ../.golangci.yml ./...

.PHONY: lint-ts
lint-ts:
	pnpm -r --if-present typecheck
	pnpm -r --if-present lint

.PHONY: lint-workflows
lint-workflows:
	$(ACTIONLINT)

.PHONY: lint-rust
lint-rust: ## clippy for the desktop shell
	cd apps/desktop/src-tauri && cargo clippy --locked --all-targets -- -D warnings

## ---------------------------------------------------------------- security

.PHONY: security
security: sec-gitleaks sec-gosec sec-govulncheck sec-osv sec-pnpm-audit sec-lockfile-age sec-semgrep sec-trivy license-check ## All security scanners

# Lockfile entries added since LOCKFILE_BASE must be >= 7 days old on npm (T-48).
# CI compares the PR merge commit with its base; locally, the default is origin/main.
LOCKFILE_BASE ?= origin/main

.PHONY: sec-lockfile-age
sec-lockfile-age: ## New pnpm-lock.yaml entries against the 7-day release-age gate
	node --test "scripts/*.test.mjs"
	node scripts/check-lockfile-age.mjs --base "$(LOCKFILE_BASE)"

.PHONY: sec-gitleaks
sec-gitleaks:
	$(call tool,gitleaks) git --redact --no-banner .
	$(call tool,gitleaks) dir --redact --no-banner --config .gitleaks.toml .

.PHONY: sec-gosec
sec-gosec:
	cd server && $(call tool,gosec) -quiet -severity medium -confidence medium -exclude-generated ./...
	cd runner && $(call tool,gosec) -quiet -severity medium -confidence medium -exclude-generated ./...

.PHONY: sec-govulncheck
sec-govulncheck:
	cd server && $(call tool,govulncheck) ./...
	cd runner && $(call tool,govulncheck) ./...

.PHONY: sec-osv
sec-osv:
	$(call tool,osv-scanner) scan source --recursive --lockfile=pnpm-lock.yaml --lockfile=server/go.mod .

.PHONY: sec-pnpm-audit
sec-pnpm-audit:
	pnpm audit --audit-level high

.PHONY: sec-semgrep
sec-semgrep: ## Needs Docker
	$(DOCKER_RUN) -v "$(CURDIR):/src" -w /src $(SEMGREP_IMG) semgrep scan --error --metrics=off \
	  --config p/owasp-top-ten --config p/golang --config p/typescript --config p/react --config .semgrep/ \
	  --exclude '**/*_gen.go' --exclude '**/*.pb.go' --exclude 'packages/api-client/src/gen' --exclude tools

.PHONY: sec-trivy
sec-trivy: ## Needs Docker
	$(DOCKER_RUN) -v "$(CURDIR):/src" -w /src $(TRIVY_IMG) config --exit-code 1 --severity HIGH,CRITICAL --skip-dirs tools --skip-dirs '**/node_modules' --skip-dirs '**/target' .
	$(DOCKER_RUN) -v "$(CURDIR):/src" -w /src $(TRIVY_IMG) fs --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed --skip-dirs tools --skip-dirs '**/node_modules' --skip-dirs '**/target' --skip-dirs '**/dist' .

.PHONY: license-check
license-check: ## Dependency licenses against the allowlist
	cd server && $(call tool,go-licenses) check ./... --ignore github.com/yamatrireddy/kilnci --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
	cd runner && $(call tool,go-licenses) check ./... --ignore github.com/yamatrireddy/kilnci --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
	node scripts/license-check.mjs
