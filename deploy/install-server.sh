#!/bin/sh
# a3 服务端一键安装（本机 Docker Compose 部署）。
# 用法: ./deploy/install-server.sh http://aa.bb.com:12345
# 完成后打开 http://aa.bb.com:12345/setup-guide（接入指南页），把该页链接发给采集端用户即可。
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$REPO_ROOT/deploy/.env"
ENV_EXAMPLE="$REPO_ROOT/deploy/.env.example"
COMPOSE_FILE="$REPO_ROOT/deploy/docker-compose.yml"

PUBLIC_URL="${1:-}"
if [ -z "$PUBLIC_URL" ]; then
  echo "用法: $0 http://<对外地址>:<端口>"
  echo "示例: $0 http://aa.bb.com:12345"
  exit 1
fi

case "$PUBLIC_URL" in
  http://*|https://*) ;;
  *) echo "❌ 地址需以 http:// 或 https:// 开头: $PUBLIC_URL"; exit 1 ;;
esac
PUBLIC_HOSTPORT="${PUBLIC_URL#*://}"
PUBLIC_HOSTPORT="${PUBLIC_HOSTPORT%%/*}"
PUBLIC_HOST="${PUBLIC_HOSTPORT%%:*}"
if [ -z "$PUBLIC_HOST" ]; then
  echo "❌ 地址缺少主机名: $PUBLIC_URL"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "❌ 未检测到 docker，请先安装 Docker 后重试"
  exit 1
fi

# —— 准备 deploy/.env ——
if [ ! -f "$ENV_FILE" ]; then
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  echo "==> 已生成 deploy/.env（含敏感口令，已由 .gitignore 排除，勿提交）"
fi

upsert_env() {
  env_key="$1"
  env_value="$2"
  if grep -q "^${env_key}=" "$ENV_FILE"; then
    sed -i.bak "s|^${env_key}=.*|${env_key}=${env_value}|" "$ENV_FILE"
    rm -f "$ENV_FILE.bak"
  else
    printf '%s=%s\n' "$env_key" "$env_value" >> "$ENV_FILE"
  fi
}

# —— 管理员口令为空则随机生成并回显 ——
ADMIN_PASSWORD_CURRENT="$(grep '^A3_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
GENERATED_PASSWORD_NOTE=""
if [ -z "$ADMIN_PASSWORD_CURRENT" ]; then
  GENERATED_PASSWORD="$(openssl rand -hex 8 2>/dev/null || head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-16)"
  upsert_env "A3_ADMIN_PASSWORD" "$GENERATED_PASSWORD"
  GENERATED_PASSWORD_NOTE="yes"
fi

# —— 公开地址与端口 ——
upsert_env "A3_PUBLIC_URL" "$PUBLIC_URL"
case "$PUBLIC_HOSTPORT" in
  *:*)
    PUBLIC_PORT="${PUBLIC_HOSTPORT##*:}"
    upsert_env "A3_HTTP_PORT" "$PUBLIC_PORT"
    ;;
  *)
    echo "==> 未从地址解析出端口，保留 A3_HTTP_PORT 现值（若经反代转发可忽略）"
    ;;
esac

# —— 非回环地址必须绑 0.0.0.0，否则局域网根本访问不到，指南链接就是死的 ——
case "$PUBLIC_HOST" in
  127.0.0.1|localhost|::1)
    ;;
  *)
    upsert_env "A3_HTTP_BIND" "0.0.0.0"
    echo "⚠️  公开地址非回环（$PUBLIC_HOST），已设 A3_HTTP_BIND=0.0.0.0 对外监听。"
    echo "    当前为明文 HTTP：请尽快前置反向代理并启用 TLS（.env 支持 A3_TLS_CERT/A3_TLS_KEY）。"
    ;;
esac

# —— 构建并拉起 postgres + server ——
echo "==> 构建镜像并启动（首次构建需数分钟）…"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build

echo
echo "✅ a3 服务端已启动"
echo "   控制台:   $PUBLIC_URL"
echo "   接入指南: $PUBLIC_URL/setup-guide  ← 把这个链接发给采集端用户"
if [ "$GENERATED_PASSWORD_NOTE" = "yes" ]; then
  echo "   管理员口令（随机生成，请尽快登录修改）: $(grep '^A3_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
fi
if ! grep -q '^A3_ALLOW_AUTO_REGISTER=true' "$ENV_FILE"; then
  echo
  echo "ℹ️  当前自动注册关闭（安全默认）。要让用户照指南页一条命令自助接入，"
  echo "    请在 deploy/.env 设置 A3_ALLOW_AUTO_REGISTER=true 后执行:"
  echo "    docker compose -f deploy/docker-compose.yml up -d"
fi
