GO ?= go
DOCKER_COMPOSE_DEV_FILE := deploy/dev/docker-compose.dev.yml

.PHONY: test build-agent build-server dev-db-up dev-db-down smoke smoke-agent offline-drill

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

# 对已启动的服务端跑终端采集器端到端冒烟；用法：
#   make smoke-agent A3_SMOKE_BASE=http://127.0.0.1:8080 A3_ADMIN_PASSWORD=***
smoke-agent:
	A3_SMOKE_BASE="$(A3_SMOKE_BASE)" A3_ADMIN_PASSWORD="$(A3_ADMIN_PASSWORD)" bash scripts/smoke-agent.sh

# 断网续传演练（用法同 smoke-agent）：断网批次落缓存 → 恢复后自动续传。
offline-drill:
	A3_SMOKE_BASE="$(A3_SMOKE_BASE)" A3_ADMIN_PASSWORD="$(A3_ADMIN_PASSWORD)" bash scripts/offline-drill.sh
