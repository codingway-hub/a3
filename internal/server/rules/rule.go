// Package rules 实现 a3 服务端风险识别引擎：
// 从 rules 表加载启用规则编译为匹配器，对标准事件做正则/glob 扫描并产出 RiskTag。
// 规则形状与终端 plugin-claude 预置清单同源（matcher JSON 形状见 migrations 种子注释）。
package rules

import (
	"encoding/json"
	"fmt"

	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/pkg/schema"
)

// 规则目标源常量。
const (
	TargetAny     = "any"     // 扫描事件全部可提取文本
	TargetCommand = "command" // 仅扫描工具输入中的命令串
	TargetPath    = "path"    // 仅扫描工具输入中的文件路径（配合 glob）
	TargetContent = "content" // 对话正文与工具结果摘要
)

// Rule 是规则的业务形状（表 rules 一行的内存形态）。
type Rule struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Category  string            `json:"category"`
	Target    string            `json:"target"`               // any|command|path|content
	Patterns  []string          `json:"patterns,omitempty"`   // 正则表达式组
	PathGlobs []string          `json:"path_globs,omitempty"` // 路径 glob 组（path 类规则）
	Severity  schema.Severity   `json:"severity"`
	Action    schema.RiskAction `json:"action"`
	Enabled   bool              `json:"enabled"`
}

// ruleMatcherShape 是 rules.matcher jsonb 的存储形状。
type ruleMatcherShape struct {
	Target    string   `json:"target"`
	Patterns  []string `json:"patterns"`
	PathGlobs []string `json:"path_globs"`
}

// FromStoreRecord 把 rules 表记录转换为业务 Rule；matcher 非法时返回错误。
func FromStoreRecord(record store.RuleRecord) (Rule, error) {
	var matcherShape ruleMatcherShape
	if unmarshalErr := json.Unmarshal(record.Matcher, &matcherShape); unmarshalErr != nil {
		return Rule{}, fmt.Errorf("规则 %s 的 matcher 不是合法 JSON: %w", record.ID, unmarshalErr)
	}
	switch matcherShape.Target {
	case TargetAny, TargetCommand, TargetPath, TargetContent:
	default:
		return Rule{}, fmt.Errorf("规则 %s 的 target 不合法: %q", record.ID, matcherShape.Target)
	}
	if len(matcherShape.Patterns) == 0 && len(matcherShape.PathGlobs) == 0 {
		return Rule{}, fmt.Errorf("规则 %s 未配置任何匹配模式", record.ID)
	}
	return Rule{
		ID:        record.ID,
		Name:      record.Name,
		Category:  record.Category,
		Target:    matcherShape.Target,
		Patterns:  matcherShape.Patterns,
		PathGlobs: matcherShape.PathGlobs,
		Severity:  schema.Severity(record.Severity),
		Action:    schema.RiskAction(record.Action),
		Enabled:   record.Enabled,
	}, nil
}
