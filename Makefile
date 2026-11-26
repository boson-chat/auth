.PHONY: setup deps run build test test-unit test-integration test-pg-up test-pg-down test-dex-up test-dex-down test-nickserv test-nickserv-up test-nickserv-down test-nickserv-clean lint migrate-up migrate-down migrate-create docker

# Load .env (if present) for run / migrate targets.
ifneq (,$(wildcard .env))
include .env
export
endif

TEST_PG_CONTAINER ?= auth-test-postgres
TEST_PG_PORT ?= 55432
TEST_DATABASE_URL ?= postgres://auth:auth-test@127.0.0.1:$(TEST_PG_PORT)/auth?sslmode=disable
TEST_DEX_CONTAINER ?= auth-test-dex
DEX_IMAGE ?= ghcr.io/dexidp/dex:v2.44.0
DEX_DISCOVERY = http://127.0.0.1:5556/dex/.well-known/openid-configuration

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

# Real OIDC provider (Dex) for TestOIDCAgainstDex; test-integration uses it
# whenever it is running.
test-dex-up:
	docker run -d --rm --name $(TEST_DEX_CONTAINER) -p 127.0.0.1:5556:5556 \
		-v $(CURDIR)/test/dex/config.yaml:/etc/dex/config.yaml:ro $(DEX_IMAGE) dex serve /etc/dex/config.yaml
	@until curl -sf $(DEX_DISCOVERY) >/dev/null; do sleep 1; done

test-dex-down:
	docker stop $(TEST_DEX_CONTAINER)

# Real services for the NickServ account backend (test/nickserv): Anope 2.1
# behind InspIRCd 4, Atheme 7.2 behind ngircd 27. Everything is in the
# compose project auth-nickserv-test (and labelled auth-nickserv-test=1).
NICKSERV_COMPOSE = docker compose -p auth-nickserv-test -f test/nickserv/compose.yaml

test-nickserv-up:
	$(NICKSERV_COMPOSE) up -d --build

test-nickserv-down:
	$(NICKSERV_COMPOSE) down -v --remove-orphans

# Also remove the fixture images built from test/nickserv.
test-nickserv-clean: test-nickserv-down
	$(NICKSERV_COMPOSE) down -v --rmi local --remove-orphans
	rm -rf test/nickserv/.certs

test-nickserv: test-nickserv-up
	TEST_NICKSERV=1 go test -race -count=1 -v ./test/nickserv/; s=$$?; $(MAKE) test-nickserv-down; exit $$s

test-integration:
	@if curl -sf -o /dev/null $(DEX_DISCOVERY); then export TEST_DEX_ISSUER=http://127.0.0.1:5556/dex; fi; \
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
