// Package schema 定义 a3 全链路统一的标准事件契约。
// 终端插件解析、服务端校验与存储均以本包为唯一权威定义；
// Schema 变更只允许追加可选字段（架构约束：长期兼容不破坏）。
package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// 事件类型常量。
const (
	EventTypeSessionStart = "session_start"
	EventTypeConversation = "conversation"
	EventTypeToolCall     = "tool_call"
	EventTypeToolResult   = "tool_result"
)

// 上报来源方式常量。
const (
	SourceMethodFileLog = "file_log"
	SourceMethodHook    = "hook"
)

// 风险等级与处置动作常量。
const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"

	RiskActionAlert RiskAction = "alert"
	RiskActionBlock RiskAction = "block"
)

// AgentTypeClaudeCode ClaudeCode 终端代理类型标识。
const AgentTypeClaudeCode = "claude-code"

// AgentTypeCodex OpenAI Codex CLI 终端代理类型标识（纯事后审计，无前置 Hook）。
const AgentTypeCodex = "codex"

// maxSummaryBytes ToolOutput.Summary 的字节上限（4KB）。
const maxSummaryBytes = 4096

// truncatedSuffix 摘要被截断后追加的标记。
const truncatedSuffix = "...(truncated)"

// Severity 风险等级："low" | "medium" | "high"。
type Severity string

// RiskAction 风险处置动作："alert" | "block"。
type RiskAction string

// RiskTag 规则命中后打在事件上的风险标签。
type RiskTag struct {
	Code        string     `json:"code"`         // 如 dlp.aws_access_key、cmd.git_force_push
	Name        string     `json:"name"`         // 中文名称（告警展示用）
	Severity    Severity   `json:"severity"`     // 风险等级
	Action      RiskAction `json:"action"`       // 处置动作
	MatchedRule string     `json:"matched_rule"` // 规则 ID
	Snippet     string     `json:"snippet"`      // 命中内容片段（已脱敏）
}

// ToolOutput 工具执行结果摘要。
type ToolOutput struct {
	IsError bool   `json:"is_error"`
	Summary string `json:"summary"` // 截断后的结果摘要（上限 4KB）
}

// Event 全链路统一的标准事件。
type Event struct {
	EventID      string          `json:"event_id"`   // 幂等键，全局唯一
	EventType    string          `json:"event_type"` // session_start|conversation|tool_call|tool_result
	AgentType    string          `json:"agent_type"` // 如 claude-code
	SessionID    string          `json:"session_id"`
	DeviceID     string          `json:"device_id"`
	OccurredAt   time.Time       `json:"occurred_at"`       // 事件发生时间
	Role         string          `json:"role,omitempty"`    // conversation: user|assistant|system
	Content      string          `json:"content,omitempty"` // Prompt 或回复文本
	ToolName     string          `json:"tool_name,omitempty"`
	ToolCallID   string          `json:"tool_call_id,omitempty"` // 关联 call↔result
	ToolInput    json.RawMessage `json:"tool_input,omitempty"`
	ToolOutput   *ToolOutput     `json:"tool_output,omitempty"`
	SourceMethod string          `json:"source_method"` // file_log|hook
	RiskTags     []RiskTag       `json:"risk_tags,omitempty"`
	Extra        json.RawMessage `json:"extra,omitempty"` // 扩展元数据（如 session_start 携带 cwd/version/gitBranch）
}

// Validate 校验事件必填字段与枚举合法性，不合法时返回描述具体字段的中文字段错误。
func (event Event) Validate() error {
	if event.EventID == "" {
		return errors.New("event_id 不能为空")
	}
	if event.EventType == "" {
		return errors.New("event_type 不能为空")
	}
	if event.AgentType == "" {
		return errors.New("agent_type 不能为空")
	}
	if event.SessionID == "" {
		return errors.New("session_id 不能为空")
	}
	if event.DeviceID == "" {
		return errors.New("device_id 不能为空")
	}
	if event.OccurredAt.IsZero() {
		return errors.New("occurred_at 不能为零值")
	}

	switch event.SourceMethod {
	case SourceMethodFileLog, SourceMethodHook:
	default:
		return fmt.Errorf("source_method 不合法: %q（允许值: file_log/hook）", event.SourceMethod)
	}

	switch event.EventType {
	case EventTypeSessionStart:
	case EventTypeConversation:
		switch event.Role {
		case "user", "assistant", "system":
		default:
			return fmt.Errorf("conversation 事件 role 不合法: %q（允许值: user/assistant/system）", event.Role)
		}
		if event.Content == "" {
			return errors.New("conversation 事件 content 不能为空")
		}
	case EventTypeToolCall:
		if event.ToolName == "" {
			return errors.New("tool_call 事件 tool_name 不能为空")
		}
		if event.ToolCallID == "" {
			return errors.New("tool_call 事件 tool_call_id 不能为空")
		}
		if len(event.ToolInput) > 0 && !json.Valid(event.ToolInput) {
			return errors.New("tool_call 事件 tool_input 不是合法的 JSON")
		}
	case EventTypeToolResult:
		if event.ToolCallID == "" {
			return errors.New("tool_result 事件 tool_call_id 不能为空")
		}
		// ToolOutput 允许为 nil：结果内容可能被抑制或过大丢弃。
	default:
		return fmt.Errorf("event_type 不合法: %q（允许值: session_start/conversation/tool_call/tool_result）", event.EventType)
	}

	for riskTagIndex := range event.RiskTags {
		if riskTagErr := event.RiskTags[riskTagIndex].Validate(); riskTagErr != nil {
			return fmt.Errorf("risk_tags[%d]: %w", riskTagIndex, riskTagErr)
		}
	}
	return nil
}

// Validate 校验风险标签必填字段与枚举合法性。
func (riskTag RiskTag) Validate() error {
	if riskTag.Code == "" {
		return errors.New("风险标签 code 不能为空")
	}
	if riskTag.Name == "" {
		return errors.New("风险标签 name 不能为空")
	}
	switch riskTag.Severity {
	case SeverityLow, SeverityMedium, SeverityHigh:
	default:
		return fmt.Errorf("风险标签 severity 不合法: %q（允许值: low/medium/high）", riskTag.Severity)
	}
	switch riskTag.Action {
	case RiskActionAlert, RiskActionBlock:
	default:
		return fmt.Errorf("风险标签 action 不合法: %q（允许值: alert/block）", riskTag.Action)
	}
	return nil
}

// TruncateSummary 按字节上限 4096 截断摘要文本：为 "...(truncated)" 后缀预留预算后按完整
// rune 边界回退截断，保证总输出恒不超过 4096 字节；未超限的文本原样返回。
func TruncateSummary(summaryText string) string {
	if len(summaryText) <= maxSummaryBytes {
		return summaryText
	}
	contentBudget := maxSummaryBytes - len(truncatedSuffix) // 为后缀预留预算，保证总输出不超上限
	truncatedText := summaryText[:contentBudget]
	// 回退到完整 rune 边界：末尾若是不完整/非法的字节序列（含仅剩首字节的情形），逐字节丢弃。
	for len(truncatedText) > 0 {
		lastRune, runeSize := utf8.DecodeLastRuneInString(truncatedText)
		if lastRune != utf8.RuneError || runeSize > 1 {
			break
		}
		truncatedText = truncatedText[:len(truncatedText)-1]
	}
	return truncatedText + truncatedSuffix
}
