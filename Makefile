# UnifiedGuard — Makefile
# Go module: git.dpnac.cloud/dpnac/central
# Requires: go 1.24+, golangci-lint (make lint), a PostgreSQL for -dsn tests.

GO      ?= go
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -X git.dpnac.cloud/dpnac/central/internal/version.gitCommit=$(COMMIT) \
           -X git.dpnac.cloud/dpnac/central/internal/version.buildDate=$(DATE)
BIN      = bin
DSN     ?= postgres://unifiedguard:test1234@127.0.0.1:55432/ug_hub_test?sslmode=disable

.PHONY: all build test lint vet clean migrate-hub migrate-fleet run-hub

all: build

## build — compile the three binaries into bin/
build:
	mkdir -p $(BIN)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/agent  ./cmd/agent
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/hub    ./cmd/hub
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/fleet  ./cmd/fleet

## test — unit tests (PG integration tests run when DSN_TEST is exported)
test:
	$(GO) test ./... $(if $(DSN_TEST),-dsn $(DSN_TEST),)

## test-pg — unit + PostgreSQL integration tests
test-pg:
	$(GO) test ./... -dsn "$(DSN)"

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

clean:
	rm -rf $(BIN)