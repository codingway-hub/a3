package claude

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/pkg/schema"
)

func parseFixtureFile(t *testing.T) []schema.Event {
	t.Helper()
	parser := NewParser()

	fixtureBytes, readErr := os.ReadFile("testdata/sample.jsonl")
	require.NoError(t, readErr)

	var allEvents []schema.Event
	for _, lineBytes := range strings.Split(string(fixtureBytes), "\n") {
		if strings.TrimSpace(lineBytes) == "" {
			continue
		}
		lineEvents, parseErr := parser.ParseLine("testdata/sample.jsonl", []byte(lineBytes))
		require.NoError(t, parseErr, "样例行均应可解析: %s", lineBytes)
		allEvents = append(allEvents, lineEvents...)
	}
	return allEvents
}

func TestParseSampleFixtureEventSequence(t *testing.T) {
	allEvents := parseFixtureFile(t)

	// L1 会话首行 → session_start + user 对话；L2 assistant 文本；L3 tool_use(Bash)；
	// L4/L5 两个 tool_result；L6 text+tool_use(Write)；L7 meta 跳过；L8 sidechain 跳过；
	// L9 system → system 对话。
	eventTypes := make([]string, 0, len(allEvents))
	for _, producedEvent := range allEvents {
		// 解析器按契约留空 DeviceID（主循环上传前填充），校验前先补齐模拟该步骤
		producedEvent.DeviceID = "dev-test-filler"
		assert.NoError(t, producedEvent.Validate(), "产出事件必须通过标准校验: %+v", producedEvent)
		eventTypes = append(eventTypes, producedEvent.EventType+"/"+producedEvent.Role)
	}
	require.Len(t, allEvents, 9)
	assert.Equal(t, []string{
		"session_start/",
		"conversation/user",
		"conversation/assistant",
		"tool_call/",
		"tool_result/",
		"tool_result/",
		"conversation/assistant",
		"tool_call/",
		"conversation/system",
	}, eventTypes)
}

func TestSessionStartExtraAndDeterministicID(t *testing.T) {
	allEvents := parseFixtureFile(t)
	sessionStart := allEvents[0]

	assert.Equal(t, schema.EventTypeSessionStart, sessionStart.EventType)
	assert.Equal(t, "sess-fixture-001", sessionStart.SessionID)

	replayEvents := parseFixtureFile(t) // 全新解析器重放同文件
	assert.Equal(t, sessionStart.EventID, replayEvents[0].EventID,
		"session_start 的 EventID 必须跨解析器实例稳定（服务端幂等依赖）")

	var extraFields map[string]string
	require.NoError(t, json.Unmarshal(sessionStart.Extra, &extraFields))
	assert.Equal(t, "/home/demo/app", extraFields["cwd"])
	assert.Equal(t, "1.0.90", extraFields["version"])
	assert.Equal(t, "main", extraFields["git_branch"])
}

func TestToolCallAndResultPairing(t *testing.T) {
	allEvents := parseFixtureFile(t)

	bashCall := findEventByToolCallID(t, allEvents, "toolu-fixture-001")
	assert.Equal(t, schema.EventTypeToolCall, bashCall.EventType)
	assert.Equal(t, "Bash", bashCall.ToolName)
	assert.JSONEq(t, `{"command":"tail -n 50 deploy.log","description":"查看部署日志末尾"}`,
		string(bashCall.ToolInput), "tool_input 应原样保留")

	okResult := findToolResultByCallID(t, allEvents, "toolu-fixture-001") // call 与 result 同 ID，须按类型区分
	require.NotNil(t, okResult.ToolOutput)
	assert.False(t, okResult.ToolOutput.IsError)
	assert.Contains(t, okResult.ToolOutput.Summary, "npm ci")

	errorResult := findErrorToolResult(t, allEvents)
	require.NotNil(t, errorResult)
	assert.Equal(t, "toolu-fixture-missing", errorResult.ToolCallID)
	require.NotNil(t, errorResult.ToolOutput)
	assert.True(t, errorResult.ToolOutput.IsError)
	assert.Contains(t, errorResult.ToolOutput.Summary, "No such file")

	// 同消息 text+tool_use：文本事件在前、工具调用在后，顺序保持
	writeIndex := indexOfEventType(allEvents, schema.EventTypeToolCall, "Write")
	textBeforeWrite := -1
	for index, producedEvent := range allEvents {
		if producedEvent.EventType == schema.EventTypeConversation &&
			producedEvent.Role == "assistant" &&
			strings.Contains(producedEvent.Content, "修正 lock 文件") {
			textBeforeWrite = index
			break
		}
	}
	require.NotEqual(t, -1, writeIndex)
	require.NotEqual(t, -1, textBeforeWrite)
	assert.Less(t, textBeforeWrite, writeIndex, "同消息内文本应先于工具调用产出")

	writeCall := allEvents[writeIndex]
	assert.JSONEq(t, `{"file_path":"/home/demo/app/package.json","content":"{ \"fixed\": true }"}`,
		string(writeCall.ToolInput))
}

func TestNoiseLinesProduceNothing(t *testing.T) {
	parser := NewParser()

	noiseLines := []string{
		`{"type":"summary","summary":"某会话摘要","leafUuid":"x"}`,
		`{"sessionId":"s","type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"sidechain"}]},"timestamp":"2026-08-23T09:00:00Z","isSidechain":true,"uuid":"u-noise-1"}`,
		`{"type":"attachment","path":"/tmp/x.png"}`,
		"",
		"   ",
	}
	for _, noiseLine := range noiseLines {
		producedEvents, parseErr := parser.ParseLine("memory.jsonl", []byte(noiseLine))
		require.NoError(t, parseErr)
		assert.Empty(t, producedEvents, "噪音行不应产出: %s", noiseLine)
	}

	// meta 行不产出内容事件，但作为会话首见归档行会触发一次 session_start
	// （否则首行为 meta 的会话将永远缺失会话开始事件）；同会话后续行不再重复。
	metaEvents, metaErr := parser.ParseLine("memory.jsonl",
		[]byte(`{"sessionId":"s2","type":"user","message":{"role":"user","content":"命令回显"},"timestamp":"2026-08-23T09:00:00Z","isMeta":true,"uuid":"u-noise-2"}`))
	require.NoError(t, metaErr)
	require.Len(t, metaEvents, 1)
	assert.Equal(t, schema.EventTypeSessionStart, metaEvents[0].EventType)

	repeatMetaEvents, repeatMetaErr := parser.ParseLine("memory.jsonl",
		[]byte(`{"sessionId":"s2","type":"user","message":{"role":"user","content":"命令回显2"},"timestamp":"2026-08-23T09:00:01Z","isMeta":true,"uuid":"u-noise-3"}`))
	require.NoError(t, repeatMetaErr)
	assert.Empty(t, repeatMetaEvents, "同会话再次出现的 meta 行完全静默")
}

func TestBadJSONLineReturnsErrorWithoutBlockingNext(t *testing.T) {
	parser := NewParser()

	_, badLineErr := parser.ParseLine("broken.jsonl", []byte(`{"type":"user","message":{"role":`))
	require.Error(t, badLineErr)
	assert.Contains(t, badLineErr.Error(), "broken.jsonl")

	_, timestampErr := parser.ParseLine("broken.jsonl",
		[]byte(`{"sessionId":"s","type":"user","message":{"role":"user","content":"hi"},"timestamp":"not-a-time","uuid":"u-bad-ts"}`))
	require.Error(t, timestampErr)
	assert.Contains(t, timestampErr.Error(), "时间戳")

	goodEvents, goodErr := parser.ParseLine("broken.jsonl",
		[]byte(`{"sessionId":"s-good","type":"user","message":{"role":"user","content":"后续正常"},"timestamp":"2026-08-23T09:30:00Z","uuid":"u-after-bad"}`))
	require.NoError(t, goodErr)
	require.Len(t, goodEvents, 2, "坏行之后的好行必须照常解析（含 session_start）")
	assert.Equal(t, "后续正常", goodEvents[1].Content)
}

// ---- 测试辅助 ----

func findEventByToolCallID(t *testing.T, events []schema.Event, toolCallID string) schema.Event {
	t.Helper()
	for _, producedEvent := range events {
		if producedEvent.ToolCallID == toolCallID {
			return producedEvent
		}
	}
	t.Fatalf("未找到 ToolCallID=%s 的事件", toolCallID)
	return schema.Event{}
}

// findToolResultByCallID 按 ToolCallID 定位 tool_result 事件
// （tool_call 与 tool_result 共享同一 ID 值，须按事件类型区分）。
func findToolResultByCallID(t *testing.T, events []schema.Event, toolCallID string) schema.Event {
	t.Helper()
	for _, producedEvent := range events {
		if producedEvent.EventType == schema.EventTypeToolResult && producedEvent.ToolCallID == toolCallID {
			return producedEvent
		}
	}
	t.Fatalf("未找到 ToolCallID=%s 的 tool_result", toolCallID)
	return schema.Event{}
}

func findErrorToolResult(t *testing.T, events []schema.Event) *schema.Event {
	t.Helper()
	for eventIndex := range events {
		candidate := &events[eventIndex]
		if candidate.EventType == schema.EventTypeToolResult && candidate.ToolOutput != nil && candidate.ToolOutput.IsError {
			return candidate
		}
	}
	t.Fatalf("未找到 is_error=true 的 tool_result")
	return nil
}

func indexOfEventType(events []schema.Event, eventType string, toolName string) int {
	for index, producedEvent := range events {
		if producedEvent.EventType == eventType && (toolName == "" || producedEvent.ToolName == toolName) {
			return index
		}
	}
	return -1
}
