.PHONY: setup run build tidy test lint migrate-up migrate-down keys db-create sqlc

GO ?= go
GOOSE ?= $(GO) run github.com/pressly/goose/v3/cmd/goose@v3.24.3
SQLC ?= $(GO) run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.29.0
DATABASE_URL ?= postgres://root:password@localhost:5432/auth?sslmode=disable
PG_ADMIN_URL ?= postgres://root:password@localhost:5432/postgres?sslmode=disable
BIN ?= bin/auth

setup: keys db-create migrate-up
	@echo "Ready. Run: make run"
	@echo "Mailpit UI: https://mail.localhost:8443/"

run:
	$(GO) run ./cmd/auth

build:
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/auth
	@echo "Built $(BIN)"

tidy:
	$(GO) mod tidy

sqlc:
	$(SQLC) generate

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

keys:
	@if [ ! -f keys/jwt-private.pem ] || [ ! -f keys/jwt-public.pem ]; then \
		./scripts/generate-jwt-keys.sh; \
	else \
		echo "JWT keys already exist"; \
	fi

db-create:
	@docker exec postgres psql -U root -tc "SELECT 1 FROM pg_database WHERE datname='auth'" | grep -q 1 \
		|| docker exec postgres psql -U root -c "CREATE DATABASE auth;"
	@echo "Database auth ready"

migrate-up:
	$(GOOSE) -dir migrations postgres "$(DATABASE_URL)" up

migrate-down:
	$(GOOSE) -dir migrations postgres "$(DATABASE_URL)" down
