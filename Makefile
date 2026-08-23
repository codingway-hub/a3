GO ?= go
DOCKER_COMPOSE_DEV_FILE := deploy/dev/docker-compose.dev.yml
DOCKER_COMPOSE_FILE := deploy/docker-compose.yml

.PHONY: test build-agent build-server build-web web-install dev-db-up dev-db-down smoke smoke-agent offline-drill compose-up compose-down release-agent

# 集成测试共享同一个本地库（a3_test），必须 -p 1 串行跑各包，避免互相 TRUNCATE 清场。
test:
	$(GO) test -p 1 ./...

build-agent:
	$(GO) build -o bin/a3-agent ./cmd/agent

build-server:
	$(GO) build -o bin/a3-server ./cmd/server

# 首次安装前端依赖（生成 web/package-lock.json）。
web-install:
	cd web && npm install

# 构建前端产物到 web/dist（服务端经 A3_WEB_DIST=./web/dist 托管）。
build-web:
	cd web && npm ci && npm run build

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

# 单机一体化部署：构建镜像并拉起 postgres+server（需先 cp deploy/.env.example deploy/.env）。
compose-up:
	docker compose -f $(DOCKER_COMPOSE_FILE) up -d --build

compose-down:
	docker compose -f $(DOCKER_COMPOSE_FILE) down

# 跨平台构建终端采集器到 bin/release/（覆盖 darwin/linux/windows 三大 GOOS）。
release-agent:
	@mkdir -p bin/release
	@for platform in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64; do \
	  releaseOS=$${platform%/*}; releaseArch=$${platform#*/}; \
	  releaseSuffix=""; [ "$$releaseOS" = "windows" ] && releaseSuffix=".exe"; \
	  echo "==> a3-agent-$$releaseOS-$$releaseArch$$releaseSuffix"; \
	  CGO_ENABLED=0 GOOS=$$releaseOS GOARCH=$$releaseArch $(GO) build -trimpath -ldflags="-s -w" \
	    -o bin/release/a3-agent-$$releaseOS-$$releaseArch$$releaseSuffix ./cmd/agent || exit 1; \
	done
