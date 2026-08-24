#!/usr/bin/env bash
# 断网续传演练：服务不可达时事件整批落本地缓存，恢复后由后台重放自动补报。
# 前置：真实服务端已启动（默认 http://127.0.0.1:8080）。
# 全程在临时沙箱 HOME 内进行，绝不触碰真实 ~/.claude 与 ~/.a3。
set -euo pipefail

BASE_URL="${A3_SMOKE_BASE:-http://127.0.0.1:8080}"
ADMIN_USER="${A3_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${A3_ADMIN_PASSWORD:?请通过 A3_ADMIN_PASSWORD 提供管理员口令}"
DEAD_URL="http://127.0.0.1:59997" # 演练用必然拒绝连接的端口

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX_HOME="$(mktemp -d "${TMPDIR:-/tmp}/a3-offline.XXXXXX")"
AGENT_PID=""
trap 'kill "$AGENT_PID" 2>/dev/null || true; rm -rf "$SANDBOX_HOME"' EXIT

# count_spool_batches 统计沙箱缓存队列批次数（find 对空目录返回 0 条且退出码为 0）。
count_spool_batches() {
  find "$HOME/.a3/spool" -maxdepth 1 -name 'batch-*.jsonl' 2>/dev/null | wc -l | tr -d ' '
}

echo "==> ① 构建采集器（bin/a3-agent 不存在时现场构建）"
AGENT_BIN="$REPO_ROOT/bin/a3-agent"
[ -x "$AGENT_BIN" ] || (cd "$REPO_ROOT" && go build -o "$AGENT_BIN" ./cmd/agent)

export HOME="$SANDBOX_HOME"

echo "==> ② 先对真实服务端注册，取得设备身份"
A3_SERVER_URL="$BASE_URL" "$AGENT_BIN" register --server "$BASE_URL" >/dev/null

PROJ_DIR="$HOME/.claude/projects/drill"
SESSION_ID="offline-drill-$(date +%s)"

echo "==> ③ 断网运行（指向 $DEAD_URL）并追加会话日志"
mkdir -p "$PROJ_DIR"
A3_SERVER_URL="$DEAD_URL" "$AGENT_BIN" run >"$SANDBOX_HOME/agent-offline.log" 2>&1 &
AGENT_PID=$!
sleep 2 # 等首轮扫描完成
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '{"sessionId":"%s","type":"user","message":{"role":"user","content":"断网期间写入的事件"},"timestamp":"%s","uuid":"%s-evt-1"}\n' \
  "$SESSION_ID" "$NOW" "$SESSION_ID" >>"$PROJ_DIR/$SESSION_ID.jsonl"
sleep 4 # 等冲刷周期触发上报（进入退避重试）

echo "==> ④ 发送 SIGTERM：在途重试应立即失败并整批转本地缓存"
EXIT_START=$(date +%s)
kill "$AGENT_PID"
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
echo "    退出耗时 $(( $(date +%s) - EXIT_START ))s"
# 用 find 计数而非 ls 通配：队列可能为空，ls 无匹配在 pipefail 下会返回非零
SPOOL_COUNT=$(count_spool_batches)
[ "$SPOOL_COUNT" -ge 1 ] || { echo "❌ 断网批次未落入本地缓存（日志见 $SANDBOX_HOME/agent-offline.log）"; exit 1; }
echo "    本地缓存批次 $SPOOL_COUNT 个"

echo "==> ⑤ 恢复网络重跑，等待缓存自动续传"
A3_SERVER_URL="$BASE_URL" "$AGENT_BIN" run >"$SANDBOX_HOME/agent-online.log" 2>&1 &
AGENT_PID=$!

LOGIN_RESPONSE=$(curl -sfS -X POST "$BASE_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}")
JWT=$(echo "$LOGIN_RESPONSE" | sed -E 's/.*"token":"([^"]+)".*/\1/')

FOUND=0
for _ in $(seq 1 40); do
  if curl -sfS "$BASE_URL/api/v1/sessions?keyword=$SESSION_ID" -H "Authorization: Bearer $JWT" \
    | grep -q "$SESSION_ID"; then
    FOUND=1
    break
  fi
  sleep 1
done
[ "$FOUND" -eq 1 ] || { echo "❌ 缓存批次未续传落库（日志见 $SANDBOX_HOME/agent-online.log）"; exit 1; }
echo "    断网期间事件已续传落库"

SPOOL_LEFT=$(count_spool_batches)
if [ "$SPOOL_LEFT" -ne 0 ]; then
  echo "⚠️ 队列仍有 $SPOOL_LEFT 个批次未清空（不影响本演练结论）"
fi

echo
echo "✅ 断网续传演练通过"
