# UnifiedGuard — Makefile
# Go module: git.dpnac.cloud/dpnac/central
# Requires: go 1.24+, golangci-lint (make lint), a PostgreSQL for -dsn tests.

GO      ?= go
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -X git.dpnac.cloud/dpnac/central/internal/version.gitCommit=$(COMMIT) \
           -X git.dpnac.cloud/dpnac/central/internal/version.buildDate=$(DATE)
BIN      = bin
DSN      ?= postgres://unifiedguard:test1234@127.0.0.1:55432/ug_hub_test?sslmode=disable
DSN_AUDIT ?= postgres://unifiedguard:test1234@127.0.0.1:55432/ug_hub_audit?sslmode=disable

.PHONY: all build test lint vet clean migrate-hub migrate-fleet run-hub preview-maquettes

all: build

## build — compile the three binaries into bin/
build:
	mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/agent  ./cmd/agent
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/hub    ./cmd/hub
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/fleet  ./cmd/fleet

## test — unit tests only (no DB required)
test:
	$(GO) test ./...

## test-pg — unit + PostgreSQL integration tests.
## WARNING: internal/audit and hub/server MUST use different DBs — `go test`
## runs packages in parallel and audit tests TRUNCATE their DB (cross-run breaks).
## Run 1: everything except internal/audit, on ug_hub_test.
## Run 2: internal/audit alone, on ug_hub_audit.
test-pg:
	UG_TEST_DSN="$(DSN)" $(GO) test $$(go list ./... | grep -v /internal/audit) -count=1
	UG_TEST_DSN="$(DSN_AUDIT)" $(GO) test ./internal/audit -count=1

## vet — go vet
vet:
	$(GO) vet ./...

## lint — golangci-lint (install it first: make lint-install)
lint:
	golangci-lint run

lint-install:
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

## migrate-hub / migrate-fleet — apply migrations with psql (dev only;
## production: the hub container runs embedded migrations at startup)
migrate-hub:
	psql "$(DSN)" -f migrations/hub/001_skeleton.sql

migrate-fleet:
	psql "$(DSN)" -f migrations/fleet/001_users.sql

## run-hub — run the hub skeleton locally
run-hub:
	HUB_LISTEN=:8080 $(GO) run ./cmd/hub

## preview-maquettes — serve docs/maquettes on http://localhost:8799
preview-maquettes:
	python3 -m http.server 8799 --directory docs/maquettes

clean:
	rm -rf $(BIN)