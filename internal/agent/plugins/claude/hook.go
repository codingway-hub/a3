package claude

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/internal/agent/core/masking"
	"github.com/codingway-hub/a3/internal/agent/core/uuidx"
	"github.com/codingway-hub/a3/pkg/schema"
)

// NamespaceA3HookEvent hook 风险事件的 v5 命名空间。
const NamespaceA3HookEvent = "b3f5b3f5-0000-5000-8000-00c04fd430c8"

// HookBlockExitCode 命中阻断规则时 ClaudeCode 约定的退出码（非零即拦截）。
const HookBlockExitCode = 2

// Plugin ClaudeCode 采集插件：解析器 + 终端规则引擎 + PreToolUse 拦截 + Hook 装卸
// （装卸方法见 installer.go）。实现 core.Plugin 五方法契约。
type Plugin struct {
	parser      *Parser
	ruleMatcher *RuleMatcher
	nowFunc     func() time.Time // 可注入确定性时间便于测试
}

// NewPlugin 构建插件并编译内置规则。
func NewPlugin(homeDir string) (*Plugin, error) {
	ruleMatcher, compileErr := NewRuleMatcher(homeDir)
	if compileErr != nil {
		return nil, compileErr
	}
	return &Plugin{
		parser:      NewParser(),
		ruleMatcher: ruleMatcher,
		nowFunc:     time.Now,
	}, nil
}

// Name 插件唯一标识。
func (claudePlugin *Plugin) Name() string { return schema.AgentTypeClaudeCode }

// LogWatchSpecs 声明 ClaudeCode 会话日志目录（~/.claude/projects/**/*.jsonl）。
func (claudePlugin *Plugin) LogWatchSpecs(homeDir string) []core.LogWatchSpec {
	return []core.LogWatchSpec{{
		RootDirectory: filepath.Join(homeDir, ".claude", "projects"),
		MatchGlob:     "*.jsonl",
	}}
}

// ParseLine 解析一行会话日志为标准事件序列。
func (claudePlugin *Plugin) ParseLine(sourcePath string, lineBytes []byte) ([]schema.Event, error) {
	return claudePlugin.parser.ParseLine(sourcePath, lineBytes)
}

// EvaluateHook 对 PreToolUse 输入做前置判定：
//   - 命中任一规则均产出 hook 来源的风险事件交上行队列（命中即取证、宁重勿漏：
//     block 是最严重的情形，更不能只依赖事后 file_log 链路补齐证据）；
//   - 命中任一 block 规则时额外阻断（Reason 为中文说明，含规则名与脱敏 snippet），
//     拦截与否仅决定退出码，不影响是否上报；
//   - 无命中：直接放行。hook 事件与 file_log 路对同一次 tool_call 各有一条记录，
//     审计场景接受少量重复以换取取证的即时与确定性；常规审计仍由 file_log 路覆盖。
func (claudePlugin *Plugin) EvaluateHook(hookRequest core.HookRequest) (core.HookDecision, error) {
	matchedTags := claudePlugin.ruleMatcher.EvaluateHookInput(hookRequest.ToolInput)
	if len(matchedTags) == 0 {
		return core.HookDecision{}, nil
	}

	var blockTag *schema.RiskTag
	for tagIndex := range matchedTags {
		if matchedTags[tagIndex].Action == schema.RiskActionBlock {
			blockTag = &matchedTags[tagIndex]
			break
		}
	}
	hookDecision := core.HookDecision{Block: blockTag != nil}
	if blockTag != nil {
		hookDecision.Reason = fmt.Sprintf("a3 已拦截：命令命中高危规则「%s」(%s)，命中片段：%s",
			blockTag.Name, blockTag.Severity, blockTag.Snippet)
	}

	// 组装风险事件上报（EventID 确定性派生，重放幂等）。
	// DeviceID 此处留空，由主循环上传前统一填充，故不做严格 Validate。
	// 幂等键取自原始输入保证跨次执行稳定；ToolInput 出站前脱敏
	// （hook 信封不经 run 的 maskEventContent，须在此收口；风险事件最小化原则下不设开关）。
	if hookRequest.SessionID == "" {
		return hookDecision, nil // 无法归属会话：仅裁决不上报
	}
	hookDecision.RiskEvents = []schema.Event{{
		EventID: uuidx.MustNewV5(NamespaceA3HookEvent,
			hookRequest.SessionID+"|"+hookRequest.ToolName+"|"+string(hookRequest.ToolInput)),
		EventType: schema.EventTypeToolCall,
		AgentType: schema.AgentTypeClaudeCode, SessionID: hookRequest.SessionID,
		OccurredAt:   claudePlugin.nowFunc().UTC(),
		ToolName:     hookRequest.ToolName,
		ToolCallID:   uuidx.MustNewV5(NamespaceA3HookEvent, "call|"+hookRequest.SessionID+"|"+hookRequest.ToolName+"|"+string(hookRequest.ToolInput)),
		ToolInput:    masking.RedactJSONLeaves(hookRequest.ToolInput),
		RiskTags:     matchedTags,
		SourceMethod: schema.SourceMethodHook,
	}}
	return hookDecision, nil
}

// RunPreToolUse CLI 入口：从 stdin 读 PreToolUse JSON，输出裁决并向 sink 提交需上报的批次。
// 返回进程退出码：0 放行、HookBlockExitCode 阻断、1 内部错误。
// envelopeSink 收到的是完整可入队的上报信封 JSON（含 agent_version/plugins/events）。
func (claudePlugin *Plugin) RunPreToolUse(stdin io.Reader, stderr io.Writer,
	envelopeSink func(envelopeBytes []byte), agentVersion string) int {

	stdinBytes, readErr := io.ReadAll(stdin)
	if readErr != nil {
		fmt.Fprintf(stderr, "a3 hook 读取输入失败: %v\n", readErr)
		return 1
	}
	var hookRequest core.HookRequest
	if unmarshalErr := json.Unmarshal(bytes.TrimSpace(stdinBytes), &hookRequest); unmarshalErr != nil {
		// 协议外输入：放行不阻断（审计工具绝不能卡死正常工作流）
		fmt.Fprintf(stderr, "a3 hook 输入不是合法 PreToolUse JSON，已放行: %v\n", unmarshalErr)
		return 0
	}

	hookDecision, decideErr := claudePlugin.EvaluateHook(hookRequest)
	if decideErr != nil {
		fmt.Fprintf(stderr, "a3 hook 判定异常，已放行: %v\n", decideErr)
		return 0
	}

	for _, riskEvent := range hookDecision.RiskEvents {
		envelopeBytes, marshalErr := json.Marshal(core.EventEnvelope{
			AgentVersion: agentVersion,
			Plugins:      []string{claudePlugin.Name()},
			Events:       []schema.Event{riskEvent},
		})
		if marshalErr == nil && envelopeSink != nil {
			envelopeSink(envelopeBytes)
		}
	}

	if hookDecision.Block {
		fmt.Fprintln(stderr, hookDecision.Reason)
		return HookBlockExitCode
	}
	return 0
}
