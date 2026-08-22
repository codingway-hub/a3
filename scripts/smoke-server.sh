#!/usr/bin/env bash
# a3 服务端冒烟验证：注册设备 → 上报含高危命令的事件 → 查会话/告警/导出。
# 前置：服务端已启动（默认 http://127.0.0.1:8080），可用 A3_SMOKE_BASE 覆盖。
set -euo pipefail

BASE_URL="${A3_SMOKE_BASE:-http://127.0.0.1:8080}"
ADMIN_USER="${A3_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${A3_ADMIN_PASSWORD:?请通过 A3_ADMIN_PASSWORD 提供管理员口令}"
FINGERPRINT="smoke-$(date +%s)"

echo "==> ① 设备注册"
REGISTER_RESPONSE=$(curl -sfS -X POST "$BASE_URL/api/v1/devices/register" \
  -H 'Content-Type: application/json' \
  -d "{\"hostname\":\"smoke-host\",\"os\":\"darwin\",\"arch\":\"arm64\",\"machine_fingerprint\":\"$FINGERPRINT\"}")
DEVICE_ID=$(echo "$REGISTER_RESPONSE" | sed -E 's/.*"device_id":"([^"]+)".*/\1/')
TOKEN=$(echo "$REGISTER_RESPONSE" | sed -E 's/.*"token":"([^"]+)".*/\1/')
echo "    device_id=$DEVICE_ID token=${TOKEN:0:12}..."

echo "==> ② 上报含高危命令的事件"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EVENTS=$(cat <<JSON
{"agent_version":"1.0.0","plugins":["claude-code"],"events":[
  {"event_id":"smoke-evt-1-$FINGERPRINT","event_type":"session_start","agent_type":"claude-code","session_id":"smoke-sess-$FINGERPRINT","device_id":"$DEVICE_ID","occurred_at":"$NOW","source_method":"file_log","extra":{"cwd":"/tmp/demo","version":"1.0.0"}},
  {"event_id":"smoke-evt-2-$FINGERPRINT","event_type":"conversation","agent_type":"claude-code","session_id":"smoke-sess-$FINGERPRINT","device_id":"$DEVICE_ID","occurred_at":"$NOW","role":"user","content":"帮我清理一下服务器","source_method":"file_log"},
  {"event_id":"smoke-evt-3-$FINGERPRINT","event_type":"tool_call","agent_type":"claude-code","session_id":"smoke-sess-$FINGERPRINT","device_id":"$DEVICE_ID","occurred_at":"$NOW","tool_name":"Bash","tool_call_id":"call-1","tool_input":{"command":"rm -rf /"},"source_method":"file_log"}
]}
JSON
)
SUBMIT_RESPONSE=$(curl -sfS -X POST "$BASE_URL/api/v1/events/batch" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" -d "$EVENTS")
echo "    $SUBMIT_RESPONSE"

echo "==> ③ 控制台登录"
LOGIN_RESPONSE=$(curl -sfS -X POST "$BASE_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}")
JWT=$(echo "$LOGIN_RESPONSE" | sed -E 's/.*"token":"([^"]+)".*/\1/')
echo "    jwt=${JWT:0:20}..."

echo "==> ④ 查询会话列表（应含风险会话）"
curl -sfS "$BASE_URL/api/v1/sessions?keyword=smoke-sess-$FINGERPRINT" -H "Authorization: Bearer $JWT"
echo

echo "==> ⑤ 查询告警（应命中 cmd.rm_rf_root）"
curl -sfS "$BASE_URL/api/v1/alerts?status=open" -H "Authorization: Bearer $JWT" | head -c 2000
echo

echo "==> ⑥ 导出会话 JSONL（前 3 行）"
curl -sfS "$BASE_URL/api/v1/sessions/$DEVICE_ID/smoke-sess-$FINGERPRINT/export" \
  -H "Authorization: Bearer $JWT" | head -n 3

echo
echo "✅ 冒烟通过"
