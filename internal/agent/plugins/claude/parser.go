// Package claude 实现 ClaudeCode CLI 采集插件：私有 JSONL 日志解析、
// 场景化风险规则、PreToolUse 前置拦截与 settings.json Hook 装卸。
package claude

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core/uuidx"
	"github.com/codingway-hub/a3/pkg/schema"
)

// Parser ClaudeCode 私有 JSONL → a3 标准事件解析器。
// 实例跨行持有会话首见状态（用于派生 session_start）；并发安全。
//
// 事件 ID 策略（端到端幂等的关键）：
//   - 源行自带 uuid 字段时直接采用（重放/重启后服务端按 EventID 去重）；
//   - 缺失时生成 v4 随机；
//   - session_start 事件固定用 v5(命名空间, sessionID) 派生——
//     agent 重启后对既有会话再次补发 session_start 也会被服务端幂等吸收。
type Parser struct {
	mu               sync.Mutex
	seenSessionIDs   map[string]struct{}
	newRandomEventID func() string // 可注入确定性 ID 便于测试
}

// NewParser 创建解析器。
func NewParser() *Parser {
	return &Parser{
		seenSessionIDs:   make(map[string]struct{}),
		newRandomEventID: uuidx.NewV4,
	}
}

// claudeLine ClaudeCode JSONL 行的私有结构（仅取审计所需字段）。
type claudeLine struct {
	Type        string          `json:"type"` // user|assistant|system|summary|...
	SessionID   string          `json:"sessionId"`
	Timestamp   string          `json:"timestamp"`
	UUID        string          `json:"uuid"`
	Cwd         string          `json:"cwd"`
	Version     string          `json:"version"`
	GitBranch   string          `json:"gitBranch"`
	IsSidechain bool            `json:"isSidechain"`
	IsMeta      bool            `json:"isMeta"`
	Subtype     string          `json:"subtype"`
	Message     *claudeMessage  `json:"message"`
	Content     json.RawMessage `json:"content"` // system 行顶层文本（string 或 block 数组）
}

// claudeMessage message 字段：role + content（string 或 block 数组）。
type claudeMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// claudeContentBlock content 数组元素：text|tool_use|tool_result|thinking|image 等。
type claudeContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"` // tool_result 结果体（string 或 block 数组）
	IsError   bool            `json:"is_error"`
}

// sessionStartExtra session_start 事件的 Extra 扩展字段。
type sessionStartExtra struct {
	Cwd       string `json:"cwd,omitempty"`
	Version   string `json:"version,omitempty"`
	GitBranch string `json:"git_branch,omitempty"`
}

// ParseLine 将一行 ClaudeCode 私有 JSONL 解析为标准事件序列。
// 返回 nil 事件与 nil 错误表示噪音行（不产出）；坏 JSON 行返回错误由调用方记录后跳过。
// 注意：事件 DeviceID 留空，由主循环在上传前按本机设备身份统一填充。
func (parser *Parser) ParseLine(sourcePath string, lineBytes []byte) ([]schema.Event, error) {
	trimmedLine := strings.TrimSpace(string(lineBytes))
	if trimmedLine == "" {
		return nil, nil
	}

	var sourceLine claudeLine
	if unmarshalErr := json.Unmarshal([]byte(trimmedLine), &sourceLine); unmarshalErr != nil {
		return nil, fmt.Errorf("JSONL 行解析失败(%s): %w", sourcePath, unmarshalErr)
	}
	if sourceLine.IsSidechain {
		return nil, nil // 子代理内部噪音：不产出
	}
	if sourceLine.SessionID == "" || sourceLine.Timestamp == "" {
		return nil, nil // 缺少会话/时间要素的行无法归档（如 summary 行）
	}
	occurredAt, timeErr := parseClaudeTimestamp(sourceLine.Timestamp)
	if timeErr != nil {
		return nil, fmt.Errorf("时间戳解析失败(%s): %w", sourcePath, timeErr)
	}

	sourceEventID := sourceLine.UUID
	if sourceEventID == "" {
		sourceEventID = parser.newRandomEventID()
	}

	var producedEvents []schema.Event
	if parser.markSessionSeen(sourceLine.SessionID) {
		sessionStartEvent, extraErr := parser.buildSessionStart(sourceLine, occurredAt)
		if extraErr != nil {
			return nil, fmt.Errorf("session_start 构造失败(%s): %w", sourcePath, extraErr)
		}
		producedEvents = append(producedEvents, sessionStartEvent)
	}

	switch sourceLine.Type {
	case "user":
		producedEvents = append(producedEvents, parser.parseUserLine(sourceLine, occurredAt, sourceEventID)...)
	case "assistant":
		producedEvents = append(producedEvents, parser.parseAssistantLine(sourceLine, occurredAt, sourceEventID)...)
	case "system":
		if systemContent := extractTextFromRaw(sourceLine.Content); systemContent != "" {
			producedEvents = append(producedEvents, schema.Event{
				EventID: sourceEventID, EventType: schema.EventTypeConversation, Role: "system",
				AgentType: schema.AgentTypeClaudeCode, SessionID: sourceLine.SessionID,
				OccurredAt: occurredAt, Content: systemContent, SourceMethod: schema.SourceMethodFileLog,
			})
		}
	default:
		// summary/attachment 等其他类型：不产出
	}
	return producedEvents, nil
}

// parseUserLine 处理 user 行：纯文本 prompt、text 块拼接（非 meta）、tool_result 块。
func (parser *Parser) parseUserLine(sourceLine claudeLine, occurredAt time.Time, sourceEventID string) []schema.Event {
	if sourceLine.Message == nil {
		return nil
	}

	// content 为纯字符串：用户 prompt
	if userText, isString := unmarshalStringRaw(sourceLine.Message.Content); isString && strings.TrimSpace(userText) != "" {
		if sourceLine.IsMeta {
			return nil // meta 行（命令回显等）：不产出
		}
		return []schema.Event{{
			EventID: sourceEventID, EventType: schema.EventTypeConversation, Role: "user",
			AgentType: schema.AgentTypeClaudeCode, SessionID: sourceLine.SessionID,
			OccurredAt: occurredAt, Content: userText, SourceMethod: schema.SourceMethodFileLog,
		}}
	}

	var contentBlocks []claudeContentBlock
	if blockErr := json.Unmarshal(sourceLine.Message.Content, &contentBlocks); blockErr != nil {
		return nil // 未知 content 形状：静默跳过
	}

	var producedEvents []schema.Event
	var textParts []string
	for _, contentBlock := range contentBlocks {
		switch contentBlock.Type {
		case "text":
			if !sourceLine.IsMeta && strings.TrimSpace(contentBlock.Text) != "" {
				textParts = append(textParts, contentBlock.Text)
			}
		case "tool_result":
			producedEvents = append(producedEvents, schema.Event{
				EventID:   parser.deriveBlockEventID(sourceEventID, "tool_result", contentBlock.ToolUseID),
				EventType: schema.EventTypeToolResult,
				AgentType: schema.AgentTypeClaudeCode, SessionID: sourceLine.SessionID,
				OccurredAt: occurredAt, ToolCallID: contentBlock.ToolUseID,
				ToolOutput: &schema.ToolOutput{
					IsError: contentBlock.IsError,
					Summary: schema.TruncateSummary(extractTextFromRaw(contentBlock.Content)),
				},
				SourceMethod: schema.SourceMethodFileLog,
			})
		}
	}
	if len(textParts) > 0 {
		producedEvents = append([]schema.Event{{
			EventID: sourceEventID, EventType: schema.EventTypeConversation, Role: "user",
			AgentType: schema.AgentTypeClaudeCode, SessionID: sourceLine.SessionID,
			OccurredAt: occurredAt, Content: strings.Join(textParts, "\n"), SourceMethod: schema.SourceMethodFileLog,
		}}, producedEvents...)
	}
	return producedEvents
}

// parseAssistantLine 处理 assistant 行：text 块 → assistant 对话；tool_use 块 → tool_call 事件。
func (parser *Parser) parseAssistantLine(sourceLine claudeLine, occurredAt time.Time, sourceEventID string) []schema.Event {
	if sourceLine.Message == nil {
		return nil
	}
	var contentBlocks []claudeContentBlock
	if blockErr := json.Unmarshal(sourceLine.Message.Content, &contentBlocks); blockErr != nil {
		return nil
	}

	var producedEvents []schema.Event
	var textParts []string
	for _, contentBlock := range contentBlocks {
		switch contentBlock.Type {
		case "text":
			if strings.TrimSpace(contentBlock.Text) != "" {
				textParts = append(textParts, contentBlock.Text)
			}
		case "tool_use":
			producedEvents = append(producedEvents, schema.Event{
				EventID:   parser.deriveBlockEventID(sourceEventID, "tool_call", contentBlock.ID),
				EventType: schema.EventTypeToolCall,
				AgentType: schema.AgentTypeClaudeCode, SessionID: sourceLine.SessionID,
				OccurredAt: occurredAt, ToolName: contentBlock.Name, ToolCallID: contentBlock.ID,
				ToolInput: contentBlock.Input, SourceMethod: schema.SourceMethodFileLog,
			})
		}
	}
	if len(textParts) > 0 {
		producedEvents = append([]schema.Event{{
			EventID: sourceEventID, EventType: schema.EventTypeConversation, Role: "assistant",
			AgentType: schema.AgentTypeClaudeCode, SessionID: sourceLine.SessionID,
			OccurredAt: occurredAt, Content: strings.Join(textParts, "\n"), SourceMethod: schema.SourceMethodFileLog,
		}}, producedEvents...)
	}
	return producedEvents
}

// buildSessionStart 构造会话开始事件（Extra 携带 cwd/version/gitBranch）。
func (parser *Parser) buildSessionStart(sourceLine claudeLine, occurredAt time.Time) (schema.Event, error) {
	extraBytes, marshalErr := json.Marshal(sessionStartExtra{
		Cwd: sourceLine.Cwd, Version: sourceLine.Version, GitBranch: sourceLine.GitBranch,
	})
	if marshalErr != nil {
		return schema.Event{}, marshalErr
	}
	return schema.Event{
		EventID: uuidx.MustNewV5(uuidx.NamespaceA3SessionStart, sourceLine.SessionID),
		EventType: schema.EventTypeSessionStart, AgentType: schema.AgentTypeClaudeCode,
		SessionID: sourceLine.SessionID, OccurredAt: occurredAt,
		Extra: extraBytes, SourceMethod: schema.SourceMethodFileLog,
	}, nil
}

// markSessionSeen 记录会话首见；返回 true 表示这是该会话在本解析器生命周期内的首行。
func (parser *Parser) markSessionSeen(sessionID string) bool {
	parser.mu.Lock()
	defer parser.mu.Unlock()
	if _, alreadySeen := parser.seenSessionIDs[sessionID]; alreadySeen {
		return false
	}
	parser.seenSessionIDs[sessionID] = struct{}{}
	return true
}

// deriveBlockEventID 为同消息内多个块派生互不冲突且重放稳定的 EventID。
func (parser *Parser) deriveBlockEventID(sourceEventID string, blockKind string, blockKey string) string {
	if blockKey != "" {
		return uuidx.MustNewV5(uuidx.NamespaceA3SessionStart, blockKind+"|"+blockKey)
	}
	return uuidx.MustNewV5(uuidx.NamespaceA3SessionStart, blockKind+"|"+sourceEventID)
}

// parseClaudeTimestamp 解析 ClaudeCode 时间戳（RFC3339，含可选纳秒）。
func parseClaudeTimestamp(timestampText string) (time.Time, error) {
	parsedTime, parseErr := time.Parse(time.RFC3339Nano, timestampText)
	if parseErr != nil {
		return time.Time{}, fmt.Errorf("无法解析时间戳 %q: %w", timestampText, parseErr)
	}
	return parsedTime, nil
}

// unmarshalStringRaw 尝试把 RawMessage 当 JSON 字符串解出。
func unmarshalStringRaw(rawContent json.RawMessage) (string, bool) {
	if len(rawContent) == 0 {
		return "", false
	}
	var textValue string
	if unmarshalErr := json.Unmarshal(rawContent, &textValue); unmarshalErr != nil {
		return "", false
	}
	return textValue, true
}

// extractTextFromRaw 从 string 或 block 数组形态的 RawMessage 提取拼接文本。
func extractTextFromRaw(rawContent json.RawMessage) string {
	if textValue, isString := unmarshalStringRaw(rawContent); isString {
		return textValue
	}
	var contentBlocks []claudeContentBlock
	if unmarshalErr := json.Unmarshal(rawContent, &contentBlocks); unmarshalErr != nil {
		return ""
	}
	var textParts []string
	for _, contentBlock := range contentBlocks {
		if contentBlock.Type == "text" && contentBlock.Text != "" {
			textParts = append(textParts, contentBlock.Text)
		}
	}
	return strings.Join(textParts, "\n")
}
