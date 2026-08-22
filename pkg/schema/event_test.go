package schema

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalValidEvent 构造一个仅含必填字段、可通过 Validate 的最小合法事件。
func minimalValidEvent() Event {
	return Event{
		EventID:      "evt-20260822-0001",
		EventType:    EventTypeSessionStart,
		AgentType:    AgentTypeClaudeCode,
		SessionID:    "session-abc123",
		DeviceID:     "device-xyz789",
		OccurredAt:   time.Date(2026, 8, 22, 10, 30, 0, 0, time.UTC),
		SourceMethod: SourceMethodFileLog,
	}
}

// minimalValidRiskTag 构造一个可通过 Validate 的最小合法风险标签。
func minimalValidRiskTag() RiskTag {
	return RiskTag{
		Code:        "dlp.aws_access_key",
		Name:        "AWS 访问密钥泄露",
		Severity:    SeverityHigh,
		Action:      RiskActionBlock,
		MatchedRule: "rule-aws-access-key",
		Snippet:     "AKIA****Q3",
	}
}

// fullyPopulatedEvent 构造一个所有字段均已赋值的事件，用于 JSON 往返一致性测试。
func fullyPopulatedEvent() Event {
	populatedEvent := minimalValidEvent()
	populatedEvent.EventType = EventTypeToolResult
	populatedEvent.SourceMethod = SourceMethodHook
	populatedEvent.Role = "assistant"
	populatedEvent.Content = "命令已执行，共返回 12 行输出"
	populatedEvent.ToolName = "Bash"
	populatedEvent.ToolCallID = "toolu_01J8XYZ"
	populatedEvent.ToolInput = json.RawMessage(`{"command":"cat config.yaml"}`)
	populatedEvent.ToolOutput = &ToolOutput{IsError: false, Summary: "命令执行成功，共 12 行输出"}
	populatedEvent.RiskTags = []RiskTag{minimalValidRiskTag()}
	populatedEvent.Extra = json.RawMessage(`{"cwd":"/Users/liu/code/a3","gitBranch":"feat/v1-mvp"}`)
	return populatedEvent
}

func TestEventValidate(t *testing.T) {
	t.Run("最小合法事件通过校验", func(t *testing.T) {
		validEvent := minimalValidEvent()
		assert.NoError(t, validEvent.Validate())
	})

	t.Run("逐项清空必填字段或填入非法枚举后校验失败", func(t *testing.T) {
		testCases := []struct {
			name        string
			mutateField func(event *Event)
		}{
			{"缺少 event_id", func(event *Event) { event.EventID = "" }},
			{"缺少 session_id", func(event *Event) { event.SessionID = "" }},
			{"缺少 event_type", func(event *Event) { event.EventType = "" }},
			{"缺少 agent_type", func(event *Event) { event.AgentType = "" }},
			{"缺少 device_id", func(event *Event) { event.DeviceID = "" }},
			{"occurred_at 为零值", func(event *Event) { event.OccurredAt = time.Time{} }},
			{"缺少 source_method", func(event *Event) { event.SourceMethod = "" }},
			{"event_type 非法", func(event *Event) { event.EventType = "unknown_type" }},
			{"source_method 非法", func(event *Event) { event.SourceMethod = "manual_input" }},
		}
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				invalidEvent := minimalValidEvent()
				testCase.mutateField(&invalidEvent)
				require.Error(t, invalidEvent.Validate())
			})
		}
	})

	t.Run("conversation 事件校验", func(t *testing.T) {
		validConversation := minimalValidEvent()
		validConversation.EventType = EventTypeConversation
		validConversation.Role = "user"
		validConversation.Content = "帮我分析一下这段报错日志"
		assert.NoError(t, validConversation.Validate())

		invalidRoleConversation := validConversation
		invalidRoleConversation.Role = "admin"
		assert.Error(t, invalidRoleConversation.Validate())

		missingRoleConversation := validConversation
		missingRoleConversation.Role = ""
		assert.Error(t, missingRoleConversation.Validate())

		missingContentConversation := validConversation
		missingContentConversation.Content = ""
		assert.Error(t, missingContentConversation.Validate())
	})

	t.Run("tool_call 事件校验", func(t *testing.T) {
		validToolCall := minimalValidEvent()
		validToolCall.EventType = EventTypeToolCall
		validToolCall.ToolName = "Bash"
		validToolCall.ToolCallID = "toolu_01J8ABC"
		validToolCall.ToolInput = json.RawMessage(`{"command":"ls -la"}`)
		assert.NoError(t, validToolCall.Validate())

		emptyInputToolCall := validToolCall
		emptyInputToolCall.ToolInput = nil
		assert.NoError(t, emptyInputToolCall.Validate(), "tool_input 为空应视为合法")

		missingToolNameToolCall := validToolCall
		missingToolNameToolCall.ToolName = ""
		assert.Error(t, missingToolNameToolCall.Validate())

		missingToolCallID := validToolCall
		missingToolCallID.ToolCallID = ""
		assert.Error(t, missingToolCallID.Validate())

		malformedInputToolCall := validToolCall
		malformedInputToolCall.ToolInput = json.RawMessage(`{"command": not-json`)
		assert.Error(t, malformedInputToolCall.Validate(), "tool_input 非法 JSON 应校验失败")
	})

	t.Run("tool_result 事件校验", func(t *testing.T) {
		validToolResult := minimalValidEvent()
		validToolResult.EventType = EventTypeToolResult
		validToolResult.ToolCallID = "toolu_01J8ABC"
		assert.NoError(t, validToolResult.Validate())

		missingToolCallIDResult := validToolResult
		missingToolCallIDResult.ToolCallID = ""
		assert.Error(t, missingToolCallIDResult.Validate())
	})
}

func TestRiskTagValidate(t *testing.T) {
	t.Run("最小合法风险标签通过校验", func(t *testing.T) {
		validRiskTag := minimalValidRiskTag()
		assert.NoError(t, validRiskTag.Validate())
	})

	t.Run("逐项清空必填字段或填入非法枚举后校验失败", func(t *testing.T) {
		testCases := []struct {
			name        string
			mutateField func(riskTag *RiskTag)
		}{
			{"缺少 code", func(riskTag *RiskTag) { riskTag.Code = "" }},
			{"缺少 name", func(riskTag *RiskTag) { riskTag.Name = "" }},
			{"severity 非法", func(riskTag *RiskTag) { riskTag.Severity = Severity("critical") }},
			{"action 非法", func(riskTag *RiskTag) { riskTag.Action = RiskAction("warn") }},
		}
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				invalidRiskTag := minimalValidRiskTag()
				testCase.mutateField(&invalidRiskTag)
				require.Error(t, invalidRiskTag.Validate())
			})
		}
	})
}

func TestEventJSONRoundTrip(t *testing.T) {
	t.Run("全字段事件 Marshal 后 Unmarshal 字段一致", func(t *testing.T) {
		originalEvent := fullyPopulatedEvent()

		encodedBytes, marshalErr := json.Marshal(originalEvent)
		require.NoError(t, marshalErr)

		var decodedEvent Event
		require.NoError(t, json.Unmarshal(encodedBytes, &decodedEvent))

		// time.Time 反序列化会丢弃单调时钟并归一化时区，先单独比较再归一后整体比较。
		assert.True(t, originalEvent.OccurredAt.Equal(decodedEvent.OccurredAt), "occurred_at 往返后应一致")
		decodedEvent.OccurredAt = originalEvent.OccurredAt
		assert.Equal(t, originalEvent, decodedEvent)
	})

	t.Run("序列化 JSON 键名符合契约", func(t *testing.T) {
		encodedBytes, marshalErr := json.Marshal(fullyPopulatedEvent())
		require.NoError(t, marshalErr)

		for _, expectedKey := range []string{
			`"event_id"`, `"event_type"`, `"agent_type"`, `"session_id"`, `"device_id"`,
			`"occurred_at"`, `"role"`, `"content"`, `"tool_name"`, `"tool_call_id"`,
			`"tool_input"`, `"tool_output"`, `"source_method"`, `"risk_tags"`, `"extra"`,
			`"is_error"`, `"summary"`,
		} {
			assert.Contains(t, string(encodedBytes), expectedKey, "JSON 中应包含键 %s", expectedKey)
		}
	})
}

func TestTruncateSummary(t *testing.T) {
	t.Run("短文本原样返回且不追加截断标记", func(t *testing.T) {
		shortSummary := "命令执行成功"
		assert.Equal(t, shortSummary, TruncateSummary(shortSummary))
	})

	t.Run("恰好达到字节上限不截断", func(t *testing.T) {
		boundarySummary := strings.Repeat("a", 4096)
		assert.Equal(t, boundarySummary, TruncateSummary(boundarySummary))
	})

	t.Run("超长 ASCII 文本按字节上限截断并追加标记", func(t *testing.T) {
		longAsciiSummary := strings.Repeat("a", 5000)
		expectedTruncated := strings.Repeat("a", 4096) + "...(truncated)"
		assert.Equal(t, expectedTruncated, TruncateSummary(longAsciiSummary))
	})

	t.Run("多字节字符回退到完整 rune 边界截断", func(t *testing.T) {
		longChineseSummary := strings.Repeat("中", 2000) // 每个汉字 3 字节，共 6000 字节
		truncatedChinese := TruncateSummary(longChineseSummary)

		assert.True(t, utf8.ValidString(truncatedChinese), "截断结果必须是合法 UTF-8 字符串")
		// 4096 字节上限内可容纳 1365 个完整汉字（4095 字节），剩余 1 字节回退丢弃。
		expectedChineseTruncated := strings.Repeat("中", 1365) + "...(truncated)"
		assert.Equal(t, expectedChineseTruncated, truncatedChinese)
	})
}

func TestEventTypeConstants(t *testing.T) {
	t.Run("事件类型常量", func(t *testing.T) {
		assert.Equal(t, "session_start", EventTypeSessionStart)
		assert.Equal(t, "conversation", EventTypeConversation)
		assert.Equal(t, "tool_call", EventTypeToolCall)
		assert.Equal(t, "tool_result", EventTypeToolResult)
	})

	t.Run("上报来源方式常量", func(t *testing.T) {
		assert.Equal(t, "file_log", SourceMethodFileLog)
		assert.Equal(t, "hook", SourceMethodHook)
	})

	t.Run("风险等级与处置动作常量", func(t *testing.T) {
		assert.Equal(t, "low", string(SeverityLow))
		assert.Equal(t, "medium", string(SeverityMedium))
		assert.Equal(t, "high", string(SeverityHigh))
		assert.Equal(t, "alert", string(RiskActionAlert))
		assert.Equal(t, "block", string(RiskActionBlock))
	})

	t.Run("终端代理类型常量", func(t *testing.T) {
		assert.Equal(t, "claude-code", AgentTypeClaudeCode)
	})
}
