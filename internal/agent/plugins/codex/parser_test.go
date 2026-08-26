package codex

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/pkg/schema"
)

// 测试用 rollout 行样本（基于本机 codex-cli 0.149.0 真实会话采样裁剪）。
const (
	fixtureSessionMeta = `{"timestamp":"2026-08-23T11:25:51.556Z","type":"session_meta",` +
		`"payload":{"session_id":"01a02e5e-926c-7331-b809-9ed56159c3dc","cwd":"/Users/demo/a3",` +
		`"cli_version":"0.149.0","git":{"branch":"feat/v1-mvp","commit_hash":"46610755"}}}`
	fixtureUserMessage = `{"timestamp":"2026-08-23T11:25:51.669Z","type":"response_item",` +
		`"payload":{"type":"message","id":"msg_01","role":"user","content":[{"type":"input_text",` +
		`"text":"帮我看看这个函数的边界条件"}]}}`
	fixtureAssistantMessage = `{"timestamp":"2026-08-23T11:26:10.717Z","type":"response_item",` +
		`"payload":{"type":"message","id":"msg_02","role":"assistant","content":[{"type":"output_text",` +
		`"text":"这个函数的边界是 n<=0 时返回零值"}]}}`
)

// mustParse 单行解析辅助：断言无错并返回事件序列。
func mustParse(t *testing.T, parser *Parser, sourcePath string, lineText string) []schema.Event {
	t.Helper()
	parsedEvents, parseErr := parser.ParseLine(sourcePath, []byte(lineText))
	require.NoError(t, parseErr)
	return parsedEvents
}

// newTestRolloutPath 构造符合 rollout 命名的测试路径（uuid 段长度合规）。
func newTestRolloutPath(sessionUUID string) string {
	return "/tmp/home/.codex/sessions/2026/08/23/rollout-2026-08-23T19-25-44-" + sessionUUID + ".jsonl"
}

func TestParseSessionMetaDerivesSessionStart(t *testing.T) {
	testParser := NewParser()
	sourcePath := newTestRolloutPath("01a02e5e-926c-7331-b809-9ed56159c3dc")
	parsedEvents := mustParse(t, testParser, sourcePath, fixtureSessionMeta)

	require.Len(t, parsedEvents, 1)
	sessionStartEvent := parsedEvents[0]
	assert.Equal(t, schema.EventTypeSessionStart, sessionStartEvent.EventType)
	assert.Equal(t, "codex", sessionStartEvent.AgentType)
	assert.Equal(t, "01a02e5e-926c-7331-b809-9ed56159c3dc", sessionStartEvent.SessionID)

	// Extra 携带 cwd/version/git_branch
	extraMap := map[string]string{}
	require.NoError(t, json.Unmarshal(sessionStartEvent.Extra, &extraMap))
	assert.Equal(t, "/Users/demo/a3", extraMap["cwd"])
	assert.Equal(t, "0.149.0", extraMap["version"])
	assert.Equal(t, "feat/v1-mvp", extraMap["git_branch"])
}

func TestParseMessageItems(t *testing.T) {
	testParser := NewParser()
	sourcePath := newTestRolloutPath("01a02e5e-926c-7331-b809-9ed56159c3dc")

	// user 消息 → conversation/user
	userEvents := mustParse(t, testParser, sourcePath, fixtureUserMessage)
	require.Len(t, userEvents, 1)
	assert.Equal(t, schema.EventTypeConversation, userEvents[0].EventType)
	assert.Equal(t, "user", userEvents[0].Role)
	assert.Equal(t, "帮我看看这个函数的边界条件", userEvents[0].Content)
}

func TestParseMessageItemsFiltering(t *testing.T) {
	testParser := NewParser()
	sourcePath := newTestRolloutPath("01a02e5e-926c-7331-b809-9ed56159c3dc")

	// developer 角色与合成前缀 user 消息：忽略
	developerLine := `{"timestamp":"2026-08-23T11:25:51.626Z","type":"response_item",` +
		`"payload":{"type":"message","id":"msg_dev","role":"developer","content":[{"type":"input_text","text":"<skills_instructions> 样板"}]}}`
	syntheticLine := `{"timestamp":"2026-08-23T11:25:51.627Z","type":"response_item",` +
		`"payload":{"type":"message","id":"msg_env","role":"user","content":[{"type":"input_text","text":"<environment_context> 沙箱说明"}]}}`
	assert.Empty(t, mustParse(t, testParser, sourcePath, developerLine))
	assert.Empty(t, mustParse(t, testParser, sourcePath, syntheticLine))
}

func TestParseFunctionCallAndOutput(t *testing.T) {
	testParser := NewParser()
	sourcePath := newTestRolloutPath("01a02e5e-926c-7331-b809-9ed56159c3dc")

	// function_call → tool_call（arguments 内嵌 JSON 字符串二次解码）
	callLine := `{"timestamp":"2026-08-23T11:26:00.000Z","type":"response_item",` +
		`"payload":{"type":"function_call","id":"fc_01","name":"exec_command","call_id":"call_01",` +
		`"arguments":"{\"cmd\":[\"ls\",\"-la\"],\"timeout\":5.0}"}}`
	callEvents := mustParse(t, testParser, sourcePath, callLine)
	require.Len(t, callEvents, 1)
	assert.Equal(t, schema.EventTypeToolCall, callEvents[0].EventType)
	assert.Equal(t, "exec_command", callEvents[0].ToolName)
	assert.Equal(t, "call_01", callEvents[0].ToolCallID)
	toolInputText := string(callEvents[0].ToolInput)
	assert.Contains(t, toolInputText, `"cmd"`)
	assert.Contains(t, toolInputText, `["ls","-la"]`)
}

func TestParseFunctionCallOutput(t *testing.T) {
	testParser := NewParser()
	sourcePath := newTestRolloutPath("01a02e5e-926c-7331-b809-9ed56159c3dc")

	// output 为对象 {output: "..."} 形态 → tool_result 摘要
	outputLine := `{"timestamp":"2026-08-23T11:26:01.000Z","type":"response_item",` +
		`"payload":{"type":"function_call_output","id":"out_01","call_id":"call_01",` +
		`"output":{"output":"total 48\n-rw-r--r-- 1 liu staff 1536 Aug 23 19:25 main.go","metadata":{}}}}`
	outputEvents := mustParse(t, testParser, sourcePath, outputLine)
	require.Len(t, outputEvents, 1)
	assert.Equal(t, schema.EventTypeToolResult, outputEvents[0].EventType)
	assert.Equal(t, "call_01", outputEvents[0].ToolCallID)
	assert.Equal(t, "total 48\n-rw-r--r-- 1 liu staff 1536 Aug 23 19:25 main.go",
		outputEvents[0].ToolOutput.Summary)
}

func TestParseIgnoresNoiseLines(t *testing.T) {
	testParser := NewParser()
	sourcePath := newTestRolloutPath("01a02e5e-926c-7331-b809-9ed56159c3dc")

	noiseLines := []string{
		`{"timestamp":"...","type":"event_msg","payload":{"type":"user_message","message":"重复流:忽略"}}`,
		`{"timestamp":"...","type":"world_state","payload":{"full":true,"state":{}}}`,
		`{"timestamp":"...","type":"turn_context","payload":{}}`,
		`{"timestamp":"...","type":"response_item","payload":{"type":"reasoning",` +
			`"summary":[{"type":"summary_text","text":"推理内容不采集"}]}}`,
	}
	for _, noiseLine := range noiseLines {
		assert.Empty(t, mustParse(t, testParser, sourcePath, noiseLine), "应忽略: %s", noiseLine)
	}

	assert.Empty(t, mustParse(t, testParser, sourcePath, ""))
	brokenEvents, brokenErr := testParser.ParseLine(sourcePath, []byte(`{broken json`))
	assert.Empty(t, brokenEvents)
	assert.Error(t, brokenErr, "坏 JSON 行应返回错误")
}

func TestDeriveSessionIDFromPath(t *testing.T) {
	assert.Equal(t, "01a02e5e-926c-7331-b809-9ed56159c3dc",
		deriveSessionIDFromPath(newTestRolloutPath("01a02e5e-926c-7331-b809-9ed56159c3dc")))
	// uuid 段长度不符 / 组数不足：返回空串
	assert.Empty(t, deriveSessionIDFromPath("/tmp/x/sessions/rollout-2026-08-23T19-25-44-short.jsonl"))
	assert.Empty(t, deriveSessionIDFromPath("/tmp/x/sessions/unrelated-name.jsonl"))
}
