.PHONY: setup run test lint migrate-up migrate-down migrate-create

setup:
	go mod download
	docker compose up -d postgres mailpit

run:
	go run ./cmd serve

test:
	go test -race ./...

lint:
	go vet ./...
