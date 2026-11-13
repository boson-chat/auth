.PHONY: setup deps run build test test-unit test-integration test-pg-up test-pg-down lint migrate-up migrate-down migrate-create docker

# Load .env (if present) for run / migrate targets.
ifneq (,$(wildcard .env))
include .env
export
endif

TEST_PG_CONTAINER ?= auth-test-postgres
TEST_PG_PORT ?= 55432
TEST_DATABASE_URL ?= postgres://auth:auth-test@127.0.0.1:$(TEST_PG_PORT)/auth?sslmode=disable

setup: deps
	docker compose up -d --wait postgres mailpit
	$(MAKE) migrate-up

deps:
	go mod download

run:
	go run ./cmd serve

build:
	CGO_ENABLED=0 go build -trimpath -o bin/auth ./cmd

test: test-unit

# Unit tests; integration tests skip unless TEST_DATABASE_URL is set.
test-unit:
	go test -race ./...

# Throwaway Postgres for the integration suite (container is started with --rm).
test-pg-up:
	docker run -d --rm --name $(TEST_PG_CONTAINER) -e POSTGRES_USER=auth -e POSTGRES_PASSWORD=auth-test \
		-p 127.0.0.1:$(TEST_PG_PORT):5432 postgres:18-alpine
	@until docker exec $(TEST_PG_CONTAINER) pg_isready -U auth -q; do sleep 1; done; sleep 1

test-pg-down:
	docker stop $(TEST_PG_CONTAINER)

test-integration:
	TEST_DATABASE_URL='$(TEST_DATABASE_URL)' go test -race -count=1 ./...

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

migrate-create:
	migrate create -ext sql -dir db/migrations -seq $(name)

migrate-up:
	go run ./cmd migrate up

migrate-down:
	go run ./cmd migrate down

docker:
	docker build -t boson-auth:dev .
