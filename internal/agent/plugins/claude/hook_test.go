package claude

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/pkg/schema"
)

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	claudePlugin, buildErr := NewPlugin(testHomeDir)
	require.NoError(t, buildErr)
	claudePlugin.nowFunc = func() time.Time { return time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC) }
	return claudePlugin
}

func TestEvaluateHookBlocksDangerousCommand(t *testing.T) {
	claudePlugin := newTestPlugin(t)

	hookDecision, decideErr := claudePlugin.EvaluateHook(core.HookRequest{
		SessionID: "sess-hook-1", ToolName: "Bash",
		ToolInput: json.RawMessage(`{"command":"rm -rf /"}`),
	})
	require.NoError(t, decideErr)
	assert.True(t, hookDecision.Block)
	assert.Contains(t, hookDecision.Reason, "已拦截")
	assert.Contains(t, hookDecision.Reason, "高危递归强删")
	require.Len(t, hookDecision.RiskEvents, 1, "命中即取证：block 也必须产出风险事件")
	require.Len(t, hookDecision.RiskEvents[0].RiskTags, 1)
	assert.Equal(t, "cmd.rm_rf_root", hookDecision.RiskEvents[0].RiskTags[0].Code)
	assert.Equal(t, schema.RiskActionBlock, hookDecision.RiskEvents[0].RiskTags[0].Action)
}

func TestEvaluateHookSafeCommandPassesSilently(t *testing.T) {
	claudePlugin := newTestPlugin(t)

	hookDecision, decideErr := claudePlugin.EvaluateHook(core.HookRequest{
		SessionID: "sess-hook-1", ToolName: "Bash",
		ToolInput: json.RawMessage(`{"command":"go test ./..."}`),
	})
	require.NoError(t, decideErr)
	assert.False(t, hookDecision.Block)
	assert.Empty(t, hookDecision.RiskEvents)
}

func TestEvaluateHookAlertOnlyProducesDeterministicRiskEvent(t *testing.T) {
	claudePlugin := newTestPlugin(t)
	alertRequest := core.HookRequest{
		SessionID: "sess-hook-alert", ToolName: "Bash",
		ToolInput: json.RawMessage(`{"command":"git reset --hard HEAD~1"}`),
	}

	firstDecision, firstErr := claudePlugin.EvaluateHook(alertRequest)
	require.NoError(t, firstErr)
	require.False(t, firstDecision.Block)
	require.Len(t, firstDecision.RiskEvents, 1)

	riskEvent := firstDecision.RiskEvents[0]
	assert.Equal(t, schema.EventTypeToolCall, riskEvent.EventType)
	assert.Equal(t, schema.SourceMethodHook, riskEvent.SourceMethod)
	assert.Equal(t, "sess-hook-alert", riskEvent.SessionID)
	require.Len(t, riskEvent.RiskTags, 1)
	assert.Equal(t, "git.history_rewrite", riskEvent.RiskTags[0].Code)
	assert.Equal(t, schema.RiskActionAlert, riskEvent.RiskTags[0].Action)

	secondDecision, secondErr := claudePlugin.EvaluateHook(alertRequest)
	require.NoError(t, secondErr)
	assert.Equal(t, riskEvent.EventID, secondDecision.RiskEvents[0].EventID,
		"同输入的 hook 风险事件 EventID 必须确定（服务端幂等依赖）")
}

func TestEvaluateHookWithoutSessionSkipsRiskEvent(t *testing.T) {
	claudePlugin := newTestPlugin(t)
	hookDecision, decideErr := claudePlugin.EvaluateHook(core.HookRequest{
		ToolName: "Bash", ToolInput: json.RawMessage(`{"command":"git reset --hard"}`),
	})
	require.NoError(t, decideErr)
	assert.False(t, hookDecision.Block)
	assert.Empty(t, hookDecision.RiskEvents)
}

func runHookCLI(t *testing.T, claudePlugin *Plugin, stdinText string) (exitCode int, stderrText string, sinkEnvelopes [][]byte) {
	t.Helper()
	var stderrBuffer bytes.Buffer
	exitCode = claudePlugin.RunPreToolUse(strings.NewReader(stdinText), &stderrBuffer,
		func(envelopeBytes []byte) { sinkEnvelopes = append(sinkEnvelopes, envelopeBytes) }, "1.0.0-test")
	return exitCode, stderrBuffer.String(), sinkEnvelopes
}

func TestRunPreToolUseBlockExitTwoWithChineseReason(t *testing.T) {
	claudePlugin := newTestPlugin(t)

	exitCode, stderrText, sinkEnvelopes := runHookCLI(t, claudePlugin,
		`{"session_id":"sess-cli","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`)
	assert.Equal(t, HookBlockExitCode, exitCode)
	assert.Contains(t, stderrText, "已拦截")
	require.Len(t, sinkEnvelopes, 1, "阻断路径同样应产出上报信封（命中即取证）")

	var blockedEnvelope core.EventEnvelope
	require.NoError(t, json.Unmarshal(sinkEnvelopes[0], &blockedEnvelope))
	require.Len(t, blockedEnvelope.Events, 1)
	assert.Equal(t, schema.SourceMethodHook, blockedEnvelope.Events[0].SourceMethod)
}

func TestRunPreToolUseAlertSinksEnvelopeAndExitsZero(t *testing.T) {
	claudePlugin := newTestPlugin(t)

	exitCode, _, sinkEnvelopes := runHookCLI(t, claudePlugin,
		`{"session_id":"sess-cli","tool_name":"Bash","tool_input":{"command":"git filter-branch --all"}}`)
	require.Equal(t, 0, exitCode)
	require.Len(t, sinkEnvelopes, 1)

	var envelope core.EventEnvelope
	require.NoError(t, json.Unmarshal(sinkEnvelopes[0], &envelope))
	assert.Equal(t, "1.0.0-test", envelope.AgentVersion)
	require.Len(t, envelope.Events, 1)
	require.Len(t, envelope.Events[0].RiskTags, 1)
	assert.Equal(t, "git.history_rewrite", envelope.Events[0].RiskTags[0].Code)
}

func TestRunPreToolUseMalformedInputPassesThrough(t *testing.T) {
	claudePlugin := newTestPlugin(t)

	exitCode, stderrText, _ := runHookCLI(t, claudePlugin, `this is not json {`)
	assert.Equal(t, 0, exitCode, "协议外输入必须放行，不得卡死工作流")
	assert.Contains(t, stderrText, "放行")
}

func TestEvaluateHookToolUseIDDerivesCallScopedEventID(t *testing.T) {
	claudePlugin := newTestPlugin(t)
	command := json.RawMessage(`{"command":"git reset --hard HEAD~1"}`)

	firstHook, firstErr := claudePlugin.EvaluateHook(core.HookRequest{
		SessionID: "sess-repeated", ToolName: "Bash",
		ToolUseID: "toolu_0001", ToolInput: command,
	})
	require.NoError(t, firstErr)
	secondHook, secondErr := claudePlugin.EvaluateHook(core.HookRequest{
		SessionID: "sess-repeated", ToolName: "Bash",
		ToolUseID: "toolu_0002", ToolInput: command,
	})
	require.NoError(t, secondErr)
	require.Len(t, firstHook.RiskEvents, 1)
	require.Len(t, secondHook.RiskEvents, 1)
	assert.NotEqual(t, firstHook.RiskEvents[0].EventID, secondHook.RiskEvents[0].EventID,
		"同会话同命令不同 tool_use_id 必须产生不同 EventID（证据不得被去重吞并）")
	assert.Equal(t, "toolu_0001", firstHook.RiskEvents[0].ToolCallID,
		"ToolCallID 应优先取宿主分配的真实调用 ID")
	assert.Equal(t, "toolu_0002", secondHook.RiskEvents[0].ToolCallID)
}

func TestEvaluateHookSameToolUseIDStaysIdempotent(t *testing.T) {
	claudePlugin := newTestPlugin(t)
	hookRequest := core.HookRequest{
		SessionID: "sess-idem", ToolName: "Bash",
		ToolUseID: "toolu_same", ToolInput: json.RawMessage(`{"command":"git reset --hard HEAD~1"}`),
	}

	firstHook, firstErr := claudePlugin.EvaluateHook(hookRequest)
	require.NoError(t, firstErr)
	secondHook, secondErr := claudePlugin.EvaluateHook(hookRequest)
	require.NoError(t, secondErr)
	assert.Equal(t, firstHook.RiskEvents[0].EventID, secondHook.RiskEvents[0].EventID,
		"同 tool_use_id 重放必须幂等（服务端去重语义依赖）")
	assert.Equal(t, "toolu_same", firstHook.RiskEvents[0].ToolCallID)
}

func TestEvaluateHookWithoutToolUseIDFallsBackToLegacySeed(t *testing.T) {
	claudePlugin := newTestPlugin(t)
	legacyRequest := core.HookRequest{
		SessionID: "sess-legacy", ToolName: "Bash",
		ToolInput: json.RawMessage(`{"command":"git reset --hard HEAD~1"}`),
	}

	firstHook, firstErr := claudePlugin.EvaluateHook(legacyRequest)
	require.NoError(t, firstErr)
	require.Len(t, firstHook.RiskEvents, 1)
	secondHook, secondErr := claudePlugin.EvaluateHook(legacyRequest)
	require.NoError(t, secondErr)
	assert.Equal(t, firstHook.RiskEvents[0].EventID, secondHook.RiskEvents[0].EventID,
		"无 tool_use_id（旧宿主）应回落旧种子：同输入仍幂等")
	assert.NotEmpty(t, firstHook.RiskEvents[0].ToolCallID, "回落路径仍需确定性 ToolCallID")
}
