package rules

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/pkg/schema"
)

// presetRules 与迁移种子同源的代表性规则子集（形状一致，便于表驱动）。
func presetRules() []Rule {
	return []Rule{
		{ID: "dlp.aws_access_key", Name: "AWS AccessKey 泄露", Category: "dlp", Target: TargetAny,
			Patterns: []string{`\bAKIA[0-9A-Z]{16}\b`}, Severity: schema.SeverityHigh, Action: schema.RiskActionBlock, Enabled: true},
		{ID: "dlp.jwt", Name: "JWT 令牌泄露", Category: "dlp", Target: TargetAny,
			Patterns: []string{`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`},
			Severity: schema.SeverityHigh, Action: schema.RiskActionBlock, Enabled: true},
		{ID: "cmd.rm_rf_root", Name: "高危递归强删(rm -rf 根/家目录)", Category: "cmd", Target: TargetCommand,
			Patterns: []string{`\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(--\s+)?(/|~|\*)`, `\brm\s+/.*\s+-[a-zA-Z]*r[a-zA-Z]*f`},
			Severity: schema.SeverityHigh, Action: schema.RiskActionBlock, Enabled: true},
		{ID: "file.ssh_private_read", Name: "敏感私钥文件访问", Category: "file", Target: TargetPath,
			PathGlobs: []string{"~/.ssh/*", "*.pem", "id_rsa*"}, Severity: schema.SeverityHigh,
			Action: schema.RiskActionBlock, Enabled: true},
		{ID: "git.history_rewrite", Name: "Git 历史重写", Category: "git", Target: TargetCommand,
			Patterns: []string{`git\s+(reset\s+--hard|filter-branch|filter-repo|rebase\s+--root)`},
			Severity: schema.SeverityMedium, Action: schema.RiskActionAlert, Enabled: true},
	}
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	// 注入确定性主目录，验证 ~/.ssh/* 形态 glob 对绝对路径的归一化命中
	engine, engineErr := NewEngine(presetRules(), "/Users/liu")
	require.NoError(t, engineErr)
	return engine
}

func mustToolCallEvent(toolName string, toolInput string) schema.Event {
	return schema.Event{
		EventID: "evt-test", EventType: schema.EventTypeToolCall, AgentType: schema.AgentTypeClaudeCode,
		SessionID: "sess-t", DeviceID: "dev-t", OccurredAt: time.Now(),
		ToolName: toolName, ToolCallID: "call-1", ToolInput: json.RawMessage(toolInput),
		SourceMethod: schema.SourceMethodFileLog,
	}
}

func TestEvaluateRuleHits(t *testing.T) {
	engine := newTestEngine(t)

	testCases := []struct {
		name           string
		event          schema.Event
		expectedCodes  []string
		unexpectedCode string
	}{
		{
			name: "对话正文中 AWS Key（target=any 扫描 content）",
			event: schema.Event{EventType: schema.EventTypeConversation, Role: "user",
				Content: "帮我把 AKIAIOSFODNN7EXAMPLE 换成新的"},
			expectedCodes: []string{"dlp.aws_access_key"},
		},
		{
			name:          "Bash 命令中的 JWT",
			event:         mustToolCallEvent("Bash", `{"command":"curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig12345' https://api.example.com"}`),
			expectedCodes: []string{"dlp.jwt"},
		},
		{
			name:          "rm -rf 根目录命中",
			event:         mustToolCallEvent("Bash", `{"command":"rm -rf /tmp/x && rm -rf /"}`),
			expectedCodes: []string{"cmd.rm_rf_root"},
		},
		{
			name:           "rm -rf 相对路径不误报",
			event:          mustToolCallEvent("Bash", `{"command":"rm -rf ./build/dist"}`),
			unexpectedCode: "cmd.rm_rf_root",
		},
		{
			name:          "Read 私钥路径命中 glob",
			event:         mustToolCallEvent("Read", `{"file_path":"/Users/liu/.ssh/id_rsa","notebook_path":""}`),
			expectedCodes: []string{"file.ssh_private_read"},
		},
		{
			name:           "Read 普通源码路径不误报",
			event:          mustToolCallEvent("Read", `{"file_path":"/Users/liu/code/a3/main.go"}`),
			unexpectedCode: "file.ssh_private_read",
		},
		{
			name: "工具结果摘要中的密钥（target=any 扫描 summary）",
			event: schema.Event{EventType: schema.EventTypeToolResult, ToolCallID: "call-1",
				ToolOutput: &schema.ToolOutput{Summary: "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}},
			expectedCodes: []string{"dlp.aws_access_key"},
		},
		{
			name:           "session_start 无扫描源不打标",
			event:          schema.Event{EventType: schema.EventTypeSessionStart, Extra: json.RawMessage(`{"cwd":"/x","note":"git reset --hard"}`)},
			unexpectedCode: "git.history_rewrite",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.event.EventID = "evt-" + strings.ReplaceAll(testCase.name, " ", "-")
			testCase.event.AgentType = schema.AgentTypeClaudeCode
			testCase.event.SessionID = "sess-t"
			testCase.event.DeviceID = "dev-t"
			testCase.event.OccurredAt = time.Now()
			testCase.event.SourceMethod = schema.SourceMethodFileLog

			riskTags := engine.Evaluate(testCase.event)
			hitCodes := make([]string, 0, len(riskTags))
			for _, riskTag := range riskTags {
				hitCodes = append(hitCodes, riskTag.Code)
			}
			for _, expectedCode := range testCase.expectedCodes {
				assert.Contains(t, hitCodes, expectedCode)
			}
			if testCase.unexpectedCode != "" {
				assert.NotContains(t, hitCodes, testCase.unexpectedCode)
			}
		})
	}
}

func TestEvaluateRiskTagShapeAndMasking(t *testing.T) {
	engine := newTestEngine(t)

	riskTags := engine.Evaluate(schema.Event{
		EventID: "evt-mask", EventType: schema.EventTypeConversation, Role: "user",
		AgentType: schema.AgentTypeClaudeCode, SessionID: "s", DeviceID: "d",
		OccurredAt: time.Now(), SourceMethod: schema.SourceMethodFileLog,
		Content: "配置里的 key 是 AKIAIOSFODNN7EXAMPLE 请帮忙检查",
	})
	require.Len(t, riskTags, 1)

	riskTag := riskTags[0]
	assert.Equal(t, "dlp.aws_access_key", riskTag.Code)
	assert.Equal(t, "AWS AccessKey 泄露", riskTag.Name)
	assert.Equal(t, schema.SeverityHigh, riskTag.Severity)
	assert.Equal(t, schema.RiskActionBlock, riskTag.Action)
	assert.Equal(t, "dlp.aws_access_key", riskTag.MatchedRule)

	// 命中文本必须脱敏：保留前 4 后 2，中间以 * 替代；不得出现完整原文
	assert.Contains(t, riskTag.Snippet, "AKIA")
	assert.NotContains(t, riskTag.Snippet, "AKIAIOSFODNN7EXAMPLE")
	assert.Regexp(t, `AKIA\*{6}LE`, riskTag.Snippet)
}

func TestSnippetContextWindow(t *testing.T) {
	longPrefix := strings.Repeat("前", 200)
	sourceText := longPrefix + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlMzQ1" + strings.Repeat("后", 200)
	engine := newTestEngine(t)

	riskTags := engine.Evaluate(schema.Event{
		EventID: "evt-win", EventType: schema.EventTypeConversation, Role: "assistant",
		AgentType: schema.AgentTypeClaudeCode, SessionID: "s", DeviceID: "d",
		OccurredAt: time.Now(), SourceMethod: schema.SourceMethodFileLog,
		Content: sourceText,
	})
	require.Len(t, riskTags, 1)
	snippetRunes := []rune(riskTags[0].Snippet)
	// 窗口 = 前后各 80 + 脱敏后命中(约12) + 首尾省略号
	assert.LessOrEqual(t, len(snippetRunes), 80+80+14+2)
	assert.True(t, strings.HasPrefix(riskTags[0].Snippet, "…"), "长上下文应以省略号开头")
}

func TestSameRuleMultipleMatchesSingleTag(t *testing.T) {
	engine := newTestEngine(t)
	riskTags := engine.Evaluate(mustToolCallEvent("Bash",
		`{"command":"echo AKIAIOSFODNN7EXAMPLE && echo AKIAIOSFODNN7EXAMPLE"}`))
	hitCount := 0
	for _, riskTag := range riskTags {
		if riskTag.Code == "dlp.aws_access_key" {
			hitCount++
		}
	}
	assert.Equal(t, 1, hitCount, "同一规则多次命中只记一个标签")
}

func TestNewEngineRejectsInvalidRegex(t *testing.T) {
	_, engineErr := NewEngine([]Rule{{ID: "bad", Patterns: []string{"([unclosed"}, Enabled: true}}, "")
	require.Error(t, engineErr)
	assert.Contains(t, engineErr.Error(), "bad 编译失败")
}

func TestDisabledRuleNotEvaluated(t *testing.T) {
	ruleList := presetRules()
	ruleList[0].Enabled = false // dlp.aws_access_key 停用
	engine, engineErr := NewEngine(ruleList, "")
	require.NoError(t, engineErr)

	riskTags := engine.Evaluate(schema.Event{
		EventID: "evt-dis", EventType: schema.EventTypeConversation, Role: "user",
		AgentType: schema.AgentTypeClaudeCode, SessionID: "s", DeviceID: "d",
		OccurredAt: time.Now(), SourceMethod: schema.SourceMethodFileLog,
		Content: "AKIAIOSFODNN7EXAMPLE",
	})
	assert.Empty(t, riskTags)
}

// storeRecordForTest 构造 store.RuleRecord 测试记录。
func storeRecordForTest(matcherJSON string, enabled bool) store.RuleRecord {
	return store.RuleRecord{ID: "dlp.aws_access_key", Name: "AWS AccessKey 泄露", Category: "dlp",
		Matcher: []byte(matcherJSON), Severity: "high", Action: "block", Enabled: enabled}
}
