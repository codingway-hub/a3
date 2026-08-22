GO ?= go
DOCKER_COMPOSE_DEV_FILE := deploy/dev/docker-compose.dev.yml

.PHONY: test build-agent build-server dev-db-up dev-db-down

test:
	$(GO) test ./...

build-agent:
	$(GO) build -o bin/a3-agent ./cmd/agent

build-server:
	$(GO) build -o bin/a3-server ./cmd/server

dev-db-up:
	docker compose -f $(DOCKER_COMPOSE_DEV_FILE) up -d

dev-db-down:
	docker compose -f $(DOCKER_COMPOSE_DEV_FILE) down
