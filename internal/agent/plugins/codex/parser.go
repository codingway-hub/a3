package codex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core/uuidx"
	"github.com/codingway-hub/a3/pkg/schema"
)

// syntheticUserPrefixes 以这些前缀开头的 user 消息是宿主注入的合成上下文，
// 非用户真实输入，审计不采集。
var syntheticUserPrefixes = []string{"<environment_context>", "<user_instructions>"}

// handledItemTypes 一期映射的 response_item 载荷类型；其余类型忽略（前向兼容）。
var handledItemTypes = map[string]struct{}{
	"message":              {},
	"function_call":        {},
	"function_call_output": {},
}

// rolloutLine rollout 行信封：type 判别字段 + 动态 payload。
type rolloutLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

// sessionMetaPayload session_meta 载荷。
type sessionMetaPayload struct {
	SessionID  string          `json:"session_id"`
	ID         string          `json:"id"`
	Cwd        string          `json:"cwd"`
	CLIVersion string          `json:"cli_version"`
	Git        *sessionMetaGit `json:"git"`
}

// sessionMetaGit session_meta.git 载荷。
type sessionMetaGit struct {
	Branch     string `json:"branch"`
	CommitHash string `json:"commit_hash"`
}

// responseItemPayload response_item 载荷：type 判别的多形态结构。
type responseItemPayload struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Role      string          `json:"role"`
	Content   []contentItem   `json:"content"`
	Name      string          `json:"name"`
	Arguments string          `json:"arguments"`
	CallID    string          `json:"call_id"`
	Output    json.RawMessage `json:"output"`
}

// contentItem message 内容块（input_text/output_text 等）。
type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// joinTextParts 拼接内容块文本。
func joinTextParts(contentBlocks []contentItem) string {
	parts := make([]string, 0, len(contentBlocks))
	for _, contentBlock := range contentBlocks {
		if contentBlock.Text != "" {
			parts = append(parts, contentBlock.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// Parser Codex rollout JSONL → a3 标准事件解析器。
// 实例跨行持有会话首见状态（用于派生 session_start）；并发安全。
type Parser struct {
	mu             sync.Mutex
	seenSessionIDs map[string]struct{}
}

// NewParser 创建解析器。
func NewParser() *Parser {
	return &Parser{seenSessionIDs: make(map[string]struct{})}
}

// ParseLine 解析一行 rollout JSONL 为标准事件序列。
// 返回 nil 事件与 nil 错误表示忽略行（不产出）；坏 JSON 行返回错误由调用方记录后跳过。
// 事件 DeviceID 留空，由主循环在上传前按本机设备身份统一填充。
func (parser *Parser) ParseLine(sourcePath string, lineBytes []byte) ([]schema.Event, error) {
	trimmedLine := strings.TrimSpace(string(lineBytes))
	if trimmedLine == "" {
		return nil, nil
	}
	var sourceLine rolloutLine
	if unmarshalErr := json.Unmarshal([]byte(trimmedLine), &sourceLine); unmarshalErr != nil {
		return nil, fmt.Errorf("rollout 行解析失败(%s): %w", sourcePath, unmarshalErr)
	}

	switch sourceLine.Type {
	case "session_meta":
		return parser.parseSessionMeta(sourceLine, sourcePath)
	case "response_item":
		return parser.parseResponseItemLine(sourceLine, sourcePath)
	default:
		// turn_context/world_state/event_msg 等其余类型：忽略
		return nil, nil
	}
}

// parseSessionMeta 处理 session_meta 行：派生 session_start 事件（重放幂等，
// v5 命名空间派生与 claude 插件同构）。
func (parser *Parser) parseSessionMeta(sourceLine rolloutLine, sourcePath string) ([]schema.Event, error) {
	var metaPayload sessionMetaPayload
	if unmarshalErr := json.Unmarshal(sourceLine.Payload, &metaPayload); unmarshalErr != nil {
		return nil, fmt.Errorf("session_meta 载荷解析失败(%s): %w", sourcePath, unmarshalErr)
	}
	sessionID := metaPayload.SessionID
	if sessionID == "" {
		sessionID = metaPayload.ID
	}
	if sessionID == "" || sourceLine.Timestamp == "" {
		return nil, nil // 缺少会话/时间要素：无法归档
	}

	gitBranch := ""
	var gitInfo *sessionMetaGit = metaPayload.Git
	if gitInfo != nil {
		gitBranch = gitInfo.Branch
	}
	extraBytes, marshalErr := json.Marshal(struct {
		Cwd       string `json:"cwd,omitempty"`
		Version   string `json:"version,omitempty"`
		GitBranch string `json:"git_branch,omitempty"`
	}{metaPayload.Cwd, metaPayload.CLIVersion, gitBranch})
	if marshalErr != nil {
		return nil, fmt.Errorf("session_start 构造失败(%s): %w", sourcePath, marshalErr)
	}
	if !parser.markSessionSeen(sessionID) {
		return nil, nil // 本解析器生命周期内已发过 session_start
	}
	occurredAt, timeErr := time.Parse(time.RFC3339Nano, sourceLine.Timestamp)
	if timeErr != nil {
		return nil, fmt.Errorf("时间戳解析失败(%s): %w", sourcePath, timeErr)
	}
	return []schema.Event{{
		EventID:      uuidx.MustNewV5(uuidx.NamespaceA3SessionStart, sessionID),
		EventType:    schema.EventTypeSessionStart,
		AgentType:    schema.AgentTypeCodex,
		SessionID:    sessionID,
		OccurredAt:   occurredAt,
		Extra:        extraBytes,
		SourceMethod: schema.SourceMethodFileLog,
	}}, nil
}

// deriveSessionIDFromPath 从 rollout 文件名解析会话 ID。
// 文件名形如 rollout-<时间戳连字符形式>-<uuidv7>.jsonl，尾部 5 组即 uuid：
// response_item 载荷不携带 session_id，文件名是重启续读时唯一稳定的会话锚点
// （session_meta 早被消费，不能依赖跨重启记忆）。
func deriveSessionIDFromPath(sourcePath string) string {
	fileStem := strings.TrimSuffix(filepath.Base(sourcePath), ".jsonl")
	stemParts := strings.Split(fileStem, "-")
	if len(stemParts) < 6 {
		return ""
	}
	uuidParts := stemParts[len(stemParts)-5:]
	for partIndex, uuidPart := range uuidParts {
		if len(uuidPart) != [...]int{8, 4, 4, 4, 12}[partIndex] {
			return ""
		}
	}
	return strings.Join(uuidParts, "-")
}

// parseResponseItemLine 处理 response_item 行：按 payload.type 分发映射。
func (parser *Parser) parseResponseItemLine(sourceLine rolloutLine, sourcePath string) ([]schema.Event, error) {
	sessionID := deriveSessionIDFromPath(sourcePath)
	if sessionID == "" {
		return nil, nil // 文件名不符合 rollout 命名：无法归属会话，忽略
	}
	var itemPayload responseItemPayload
	if unmarshalErr := json.Unmarshal(sourceLine.Payload, &itemPayload); unmarshalErr != nil {
		return nil, fmt.Errorf("response_item 载荷解析失败(%s): %w", sourcePath, unmarshalErr)
	}
	if _, isHandled := handledItemTypes[itemPayload.Type]; !isHandled {
		return nil, nil // reasoning/未知类型：一期忽略，不因时间戳等要素失败（前向兼容）
	}
	occurredAt, timeErr := time.Parse(time.RFC3339Nano, sourceLine.Timestamp)
	if timeErr != nil {
		return nil, fmt.Errorf("时间戳解析失败(%s): %w", sourcePath, timeErr)
	}

	switch itemPayload.Type {
	case "message":
		return parser.parseMessageItem(itemPayload, sessionID, occurredAt)
	case "function_call":
		return parser.parseFunctionCallItem(itemPayload, sessionID, occurredAt)
	case "function_call_output":
		return parser.parseFunctionCallOutputItem(itemPayload, sessionID, occurredAt)
	default:
		// reasoning/custom_tool_call*/web_search_call* 等：一期忽略
		return nil, nil
	}
}

// parseMessageItem message 项：user/assistant 文本 → conversation 事件；
// developer/system 角色是每轮注入的指令样板，忽略；合成前缀 user 消息同样忽略。
func (parser *Parser) parseMessageItem(itemPayload responseItemPayload, sessionID string,
	occurredAt time.Time) ([]schema.Event, error) {
	messageText := joinTextParts(itemPayload.Content)
	if messageText == "" {
		return nil, nil
	}
	switch itemPayload.Role {
	case "user":
		for _, syntheticPrefix := range syntheticUserPrefixes {
			if strings.HasPrefix(messageText, syntheticPrefix) {
				return nil, nil
			}
		}
	case "assistant":
	default:
		return nil, nil // developer/system 等角色：忽略
	}
	return []schema.Event{{
		EventID:      resolveEventID(itemPayload.ID, itemPayload.CallID),
		EventType:    schema.EventTypeConversation,
		Role:         itemPayload.Role,
		AgentType:    schema.AgentTypeCodex,
		SessionID:    sessionID,
		OccurredAt:   occurredAt,
		Content:      messageText,
		SourceMethod: schema.SourceMethodFileLog,
	}}, nil
}

// parseFunctionCallItem function_call 项 → tool_call 事件。
// arguments 是「内嵌 JSON 的字符串」，需二次解码；解析保持键名无关。
func (parser *Parser) parseFunctionCallItem(itemPayload responseItemPayload, sessionID string,
	occurredAt time.Time) ([]schema.Event, error) {
	if itemPayload.CallID == "" {
		return nil, nil // 无 call_id 无法关联后续 tool_result：忽略
	}
	return []schema.Event{{
		EventID:      resolveEventID(itemPayload.ID, itemPayload.CallID),
		EventType:    schema.EventTypeToolCall,
		AgentType:    schema.AgentTypeCodex,
		SessionID:    sessionID,
		OccurredAt:   occurredAt,
		ToolName:     itemPayload.Name,
		ToolCallID:   itemPayload.CallID,
		ToolInput:    decodeArgumentsJSON(itemPayload.Arguments),
		SourceMethod: schema.SourceMethodFileLog,
	}}, nil
}

// parseFunctionCallOutputItem function_call_output 项 → tool_result 事件。
// output 可能是字符串或对象（含 output/content 字段），提取文本后截断为摘要。
func (parser *Parser) parseFunctionCallOutputItem(itemPayload responseItemPayload, sessionID string,
	occurredAt time.Time) ([]schema.Event, error) {
	if itemPayload.CallID == "" {
		return nil, nil
	}
	outputText := extractOutputText(itemPayload.Output)
	if outputText == "" {
		return nil, nil
	}
	return []schema.Event{{
		EventID:    resolveEventID(itemPayload.ID, itemPayload.CallID),
		EventType:  schema.EventTypeToolResult,
		AgentType:  schema.AgentTypeCodex,
		SessionID:  sessionID,
		OccurredAt: occurredAt,
		ToolCallID: itemPayload.CallID,
		ToolOutput: &schema.ToolOutput{
			Summary: schema.TruncateSummary(outputText),
		},
		SourceMethod: schema.SourceMethodFileLog,
	}}, nil
}

// decodeArgumentsJSON 把「内嵌 JSON 的 arguments 字符串」转为 RawMessage；
// 内层不是合法 JSON 时降级为 JSON 字符串值，保证下游序列化恒有效。
func decodeArgumentsJSON(argumentsText string) json.RawMessage {
	trimmedText := strings.TrimSpace(argumentsText)
	if trimmedText == "" {
		return nil
	}
	if json.Valid([]byte(trimmedText)) {
		return json.RawMessage(trimmedText)
	}
	quotedBytes, quoteErr := json.Marshal(argumentsText)
	if quoteErr != nil {
		return nil
	}
	return quotedBytes
}

// extractOutputText 从 tool_result 的 output 载荷提取文本：
// 字符串直接取；对象优先取 output/content 字符串字段；其余紧凑序列化兜底。
func extractOutputText(outputRaw json.RawMessage) string {
	if len(outputRaw) == 0 {
		return ""
	}
	var outputText string
	if unmarshalErr := json.Unmarshal(outputRaw, &outputText); unmarshalErr == nil {
		return outputText
	}
	var outputObject struct {
		Output  string `json:"output"`
		Content string `json:"content"`
	}
	if unmarshalErr := json.Unmarshal(outputRaw, &outputObject); unmarshalErr == nil {
		if outputObject.Output != "" {
			return outputObject.Output
		}
		if outputObject.Content != "" {
			return outputObject.Content
		}
	}
	compactBuffer := &bytes.Buffer{}
	if compactErr := json.Compact(compactBuffer, outputRaw); compactErr == nil {
		return compactBuffer.String()
	}
	return string(outputRaw)
}

// resolveEventID 稳定事件 ID：优先源行自带 id，其次 call_id 派生（重放幂等）。
func resolveEventID(itemID string, callID string) string {
	if itemID != "" {
		return itemID
	}
	if callID != "" {
		return uuidx.MustNewV5(uuidx.NamespaceA3SessionStart, "call|"+callID)
	}
	return uuidx.NewV4()
}

// markSessionSeen 记录会话首见；返回 true 表示该会话在本解析器生命周期内的首行。
func (parser *Parser) markSessionSeen(sessionID string) bool {
	parser.mu.Lock()
	defer parser.mu.Unlock()
	if _, alreadySeen := parser.seenSessionIDs[sessionID]; alreadySeen {
		return false
	}
	parser.seenSessionIDs[sessionID] = struct{}{}
	return true
}
