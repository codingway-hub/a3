GO ?= go
DOCKER_COMPOSE_DEV_FILE := deploy/dev/docker-compose.dev.yml

.PHONY: test build-agent build-server dev-db-up dev-db-down smoke

# 集成测试共享同一个本地库（a3_test），必须 -p 1 串行跑各包，避免互相 TRUNCATE 清场。
test:
	$(GO) test -p 1 ./...

build-agent:
	$(GO) build -o bin/a3-agent ./cmd/agent

build-server:
	$(GO) build -o bin/a3-server ./cmd/server

dev-db-up:
	docker compose -f $(DOCKER_COMPOSE_DEV_FILE) up -d

dev-db-down:
	docker compose -f $(DOCKER_COMPOSE_DEV_FILE) down

# 对已启动的服务端跑冒烟脚本；需先 export A3_SMOKE_BASE 与 A3_ADMIN_PASSWORD。
smoke:
	bash scripts/smoke-server.sh
