#!/usr/bin/env bash
# a3 终端采集器端到端冒烟：register → install-hook → hook 拦截/alert 入队 → run 采集上报。
# 前置：服务端已启动（默认 http://127.0.0.1:8080），可用 A3_SMOKE_BASE 覆盖；
#       A3_ADMIN_PASSWORD 必填（控制台登录用于核对数据落库）。
# 全程在临时沙箱 HOME 内进行，绝不触碰真实 ~/.claude 与 ~/.a3。
set -euo pipefail

BASE_URL="${A3_SMOKE_BASE:-http://127.0.0.1:8080}"
ADMIN_USER="${A3_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${A3_ADMIN_PASSWORD:?请通过 A3_ADMIN_PASSWORD 提供管理员口令}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX_HOME="$(mktemp -d "${TMPDIR:-/tmp}/a3-agent-smoke.XXXXXX")"
AGENT_PID=""
trap 'kill "$AGENT_PID" 2>/dev/null || true; rm -rf "$SANDBOX_HOME"' EXIT

echo "==> ① 构建采集器二进制"
AGENT_BIN="$SANDBOX_HOME/a3-agent"
(cd "$REPO_ROOT" && go build -o "$AGENT_BIN" ./cmd/agent)

export HOME="$SANDBOX_HOME"
export A3_SERVER_URL="$BASE_URL"

# register_device / register_or_selfheal：同机指纹重复演练会撞 B1 凭证规则
# （指纹与 HOME 无关），此时经管理员控制台吊销旧 active 设备后再重建。
register_device() {
  "$AGENT_BIN" register --server "$BASE_URL" >"$SANDBOX_HOME/register.log" 2>&1
}
register_or_selfheal() {
  if register_device; then
    return 0
  fi
  if grep -q "需携带既有 Token" "$SANDBOX_HOME/register.log"; then
    echo "    同机指纹已登记：以管理员身份吊销旧设备后重新注册"
    MACHINE_SHORT_HOSTNAME="$(hostname | cut -d. -f1)"
    REVOKE_JWT=$(curl -sfS -X POST "$BASE_URL/api/v1/auth/login" \
      -H 'Content-Type: application/json' \
      -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}" \
      | sed -E 's/.*"token":"([^"]+)".*/\1/')
    OLD_DEVICE_ID=$(curl -sfS "$BASE_URL/api/v1/devices" -H "Authorization: Bearer $REVOKE_JWT" \
      | jq -r --arg hostname "$MACHINE_SHORT_HOSTNAME" \
          '.items[] | select(.hostname==$hostname and .status=="active") | .device_id' | head -1)
    [ -n "$OLD_DEVICE_ID" ] || { echo "❌ 未找到同机 active 设备可吊销"; cat "$SANDBOX_HOME/register.log"; exit 1; }
    curl -sfS -X PATCH "$BASE_URL/api/v1/devices/$OLD_DEVICE_ID" \
      -H "Authorization: Bearer $REVOKE_JWT" -H 'Content-Type: application/json' \
      -d '{"status":"revoked"}' >/dev/null
    echo "    已吊销 $OLD_DEVICE_ID"
  else
    echo "❌ 设备注册失败"; cat "$SANDBOX_HOME/register.log"; exit 1
  fi
  register_device || { echo "❌ 吊销后重新注册仍失败"; cat "$SANDBOX_HOME/register.log"; exit 1; }
}

echo "==> ② 显式注册设备"
register_or_selfheal
DEVICE_ID=$(cat "$HOME/.a3/device-id")
echo "    device_id=$DEVICE_ID"

echo "==> ③ 安装 PreToolUse Hook"
"$AGENT_BIN" install-hook
grep -q "hook pretooluse" "$HOME/.claude/settings.json"

echo "==> ④ Hook 拦截演练：rm -rf / 应阻断（退出码 2）"
set +e
BLOCK_OUTPUT=$(printf '%s' '{"session_id":"smoke-hook","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | "$AGENT_BIN" hook pretooluse 2>&1)
BLOCK_CODE=$?
set -e
[ "$BLOCK_CODE" -eq 2 ] || { echo "❌ 高危命令未被以退出码 2 拦截（实际 ${BLOCK_CODE}）：${BLOCK_OUTPUT}"; exit 1; }
echo "$BLOCK_OUTPUT" | grep -q "已拦截" || { echo "❌ 阻断原因缺失：$BLOCK_OUTPUT"; exit 1; }
echo "    已拦截(exit=2)"

echo "==> ⑤ Hook alert 演练：git reset --hard 放行且风险事件入本地缓存"
printf '%s' '{"session_id":"smoke-hook","tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"}}' \
  | "$AGENT_BIN" hook pretooluse 2>/dev/null
SPOOL_COUNT=$(find "$HOME/.a3/spool/incoming" -maxdepth 1 -name 'batch-*.jsonl' 2>/dev/null | wc -l | tr -d ' ')
[ "$SPOOL_COUNT" -ge 1 ] || { echo "❌ alert 风险事件未入缓存队列"; exit 1; }
echo "    本地缓存批次 $SPOOL_COUNT 个"

echo "==> ⑥ 控制台登录（后续核对落库）"
LOGIN_RESPONSE=$(curl -sfS -X POST "$BASE_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}")
JWT=$(echo "$LOGIN_RESPONSE" | sed -E 's/.*"token":"([^"]+)".*/\1/')

echo "==> ⑦ 常驻采集启动并追加合成会话日志"
SESSION_ID="smoke-run-$(date +%s)"
"$AGENT_BIN" run >"$SANDBOX_HOME/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1 # 等首轮扫描完成；此后新建文件按「运行期新建」从头消费

PROJ_DIR="$HOME/.claude/projects/smoke-proj"
mkdir -p "$PROJ_DIR"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat >> "$PROJ_DIR/$SESSION_ID.jsonl" <<JSONL
{"sessionId":"$SESSION_ID","type":"user","message":{"role":"user","content":"帮我清理一下服务器日志"},"timestamp":"$NOW","uuid":"$SESSION_ID-evt-1","cwd":"/tmp/demo","version":"0.0.0","gitBranch":"main"}
{"sessionId":"$SESSION_ID","type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"call-smoke-1","name":"Bash","input":{"command":"rm -rf /tmp/logs-archive"}}]},"timestamp":"$NOW","uuid":"$SESSION_ID-evt-2"}
JSONL

echo "==> ⑧ 轮询等待会话与告警落库"
FOUND_SESSION=0
for _ in $(seq 1 30); do
  if curl -sfS "$BASE_URL/api/v1/sessions?keyword=$SESSION_ID" -H "Authorization: Bearer $JWT" \
      | grep -q "$SESSION_ID"; then
    FOUND_SESSION=1
    break
  fi
  sleep 1
done
[ "$FOUND_SESSION" -eq 1 ] || { echo "❌ 会话未上报落库（agent.log 见 $SANDBOX_HOME/agent.log）"; exit 1; }
echo "    会话已落库"

FOUND_ALERT=0
for _ in $(seq 1 15); do
  if curl -sfS "$BASE_URL/api/v1/alerts?status=open" -H "Authorization: Bearer $JWT" \
      | grep -q "cmd.rm_rf_root"; then
    FOUND_ALERT=1
    break
  fi
  sleep 1
done
[ "$FOUND_ALERT" -eq 1 ] || { echo "❌ rm -rf 工具调用未产生服务端告警"; exit 1; }
echo "    告警已触发(cmd.rm_rf_root)"

echo "==> ⑨ 卸载 Hook 并确认还原"
"$AGENT_BIN" uninstall-hook
if grep -q "hook pretooluse" "$HOME/.claude/settings.json" 2>/dev/null; then
  echo "❌ 卸载后仍残留 a3 Hook"; exit 1
fi

echo
echo "✅ 终端采集器冒烟通过"
