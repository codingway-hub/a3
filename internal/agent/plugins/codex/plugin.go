package codex

import (
	"os"
	"path/filepath"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/pkg/schema"
)

// Plugin OpenAI Codex CLI 采集插件：rollout JSONL 解析器，纯事后审计。
// 相对 claude 插件刻意裁剪：无规则引擎与 Hook 装卸（无前置阻断能力）。
type Plugin struct {
	parser *Parser
}

// NewPlugin 构建 Codex 插件实例。
func NewPlugin() (*Plugin, error) {
	return &Plugin{parser: NewParser()}, nil
}

// Name 插件唯一标识。
func (codexPlugin *Plugin) Name() string { return schema.AgentTypeCodex }

// LogWatchSpecs 声明 Codex 会话日志目录（~/.codex/sessions 递归 *.jsonl）。
// rollout 按日期分片目录，watcher 的 WalkDir 递归遍历天然覆盖，MatchGlob 按
// base 名匹配无需目录深度假设；$CODEX_HOME 可整体迁移根目录。
func (codexPlugin *Plugin) LogWatchSpecs(homeDir string) []core.LogWatchSpec {
	rootDirectory := filepath.Join(homeDir, ".codex", "sessions")
	if customHome := os.Getenv("CODEX_HOME"); customHome != "" {
		rootDirectory = filepath.Join(customHome, "sessions")
	}
	return []core.LogWatchSpec{{
		RootDirectory: rootDirectory,
		MatchGlob:     "*.jsonl",
	}}
}

// ParseLine 解析一行 rollout JSONL 为标准事件序列（委托解析器）。
func (codexPlugin *Plugin) ParseLine(sourcePath string, lineBytes []byte) ([]schema.Event, error) {
	return codexPlugin.parser.ParseLine(sourcePath, lineBytes)
}

// EvaluateHook Codex 无前置 Hook 能力：恒放行、零事件（纯审计定位）。
func (codexPlugin *Plugin) EvaluateHook(hookRequest core.HookRequest) (core.HookDecision, error) {
	return core.HookDecision{}, nil
}

// ConfigureHook Codex 无宿主配置可装卸：返回哨兵错误供装配层给出友好提示。
func (codexPlugin *Plugin) ConfigureHook(homeDir string, enable bool) (bool, error) {
	return false, core.ErrHookUnsupported
}
