package core

import (
	"encoding/json"
	"io"

	"github.com/codingway-hub/a3/pkg/schema"
)

// LogWatchSpec 插件声明的日志监听位置：Core 据此驱动文件监听引擎。
type LogWatchSpec struct {
	RootDirectory string // 监听根目录（已展开的绝对路径）
	MatchGlob     string // 文件名匹配 glob，如 "*.jsonl"
}

// HookRequest 宿主工具前置 Hook 的 stdin 输入（ClaudeCode PreToolUse 协议子集）。
// ToolUseID 为本次工具调用的唯一 ID（宿主分配，如 toolu_xxx）：并入 v5 事件种子
// 后，同会话重复执行相同命令也能得到不同 event_id，避免服务端去重吞证。
type HookRequest struct {
	SessionID string          `json:"session_id"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	ToolUseID string          `json:"tool_use_id"`
}

// HookDecision 插件对一次 Hook 调用的裁决：
// Block 为真时宿主应阻断该工具调用；RiskEvents 为需要上行上报的风险事件
// （hook 路径只报风险增量，常规审计由 file_log 路覆盖，避免双份重复）。
type HookDecision struct {
	Block      bool
	Reason     string         // 阻断/提示原因（中文，含规则名与脱敏 snippet）
	RiskEvents []schema.Event // 需交上行队列的风险事件（可为空）
}

// Plugin 终端采集插件基干接口：所有 Agent 差异化能力收敛于此，Core 只依赖本接口
// （新增 AI Agent 零改动接入）。仅声明通用采集能力——具备宿主前置拦截能力的
// 插件额外实现 PreToolUsePlugin，由装配层类型断言探测，而非强制全部实现。
type Plugin interface {
	// Name 插件唯一标识（如 claude-code），注册表据此去重。
	Name() string

	// LogWatchSpecs 声明需要监听的日志目录与文件规则；
	// homeDir 为当前用户主目录（插件据此推导工具私有日志路径）。
	LogWatchSpecs(homeDir string) []LogWatchSpec

	// ParseLine 将一行私有日志解析为标准事件序列；噪音行返回 nil 不产出事件。
	ParseLine(sourcePath string, line []byte) ([]schema.Event, error)
}

// PreToolUsePlugin 宿主 PreToolUse 前置拦截能力（可选能力）：
// 实现本接口的插件具备本地前后置拦截，可被装配层安装/卸载 Hook（ConfigureHook）、
// 逐次放行/阻断裁决（EvaluateHook）并作为宿主 CLI 入口运行（RunPreToolUse）。
// 纯审计型插件（如 codex）刻意不实现——装配层以类型断言探测到缺席时走友好提示
// 或 fail-open，不再靠哨兵错误短路每处调用。
type PreToolUsePlugin interface {
	Plugin
	EvaluateHook(hookRequest HookRequest) (HookDecision, error)
	ConfigureHook(homeDir string, enable bool) (changed bool, err error)
	RunPreToolUse(stdin io.Reader, stderr io.Writer, envelopeSink func(envelopeBytes []byte), agentVersion string) int
}
