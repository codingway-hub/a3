package rules

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/codingway-hub/a3/pkg/schema"
)

// Engine 持有编译后的启用规则集，对标准事件做无状态扫描。
type Engine struct {
	compiledRules []*compiledRule
}

// NewEngine 编译规则集；任一规则非法即报错（调用方应保证入库前已校验）。
// homeDir 供 ~/.ssh/* 形态 glob 做主目录归一化；传空串则跳过归一化候选。
func NewEngine(ruleList []Rule, homeDir string) (*Engine, error) {
	engine := &Engine{compiledRules: make([]*compiledRule, 0, len(ruleList))}
	for _, rule := range ruleList {
		if !rule.Enabled {
			continue // 停用规则不参与编译
		}
		compiled, compileErr := compileRule(rule, homeDir)
		if compileErr != nil {
			return nil, fmt.Errorf("规则 %s 编译失败: %w", rule.ID, compileErr)
		}
		engine.compiledRules = append(engine.compiledRules, compiled)
	}
	return engine, nil
}

// NewSystemEngine 以当前进程用户主目录构建引擎（服务端装配入口）。
func NewSystemEngine(ruleList []Rule) (*Engine, error) {
	userHomeDir, homeErr := os.UserHomeDir()
	if homeErr != nil {
		userHomeDir = ""
	}
	return NewEngine(ruleList, userHomeDir)
}

// Evaluate 扫描事件并返回全部命中风险标签（去重：同规则只记首个命中）。
// 事件无风险时返回空切片。
func (engine *Engine) Evaluate(event schema.Event) []schema.RiskTag {
	commandSources, pathSources, textSources := eventScanSources(event)

	riskTags := make([]schema.RiskTag, 0)
	for _, compiled := range engine.compiledRules {
		var hit *matchHit
		switch compiled.rule.Target {
		case TargetCommand:
			hit = matchFirst(compiled, commandSources)
		case TargetPath:
			hit = matchFirstPath(compiled, pathSources)
		case TargetContent:
			hit = matchFirst(compiled, textSources)
		case TargetAny:
			hit = matchFirst(compiled, commandSources)
			if hit == nil {
				hit = matchFirstPath(compiled, pathSources)
			}
			if hit == nil {
				hit = matchFirst(compiled, textSources)
			}
		}
		if hit != nil {
			riskTags = append(riskTags, compiled.riskTag(hit))
		}
	}
	return riskTags
}

// matchFirst 依次扫描源串列表，返回首个命中。
func matchFirst(compiled *compiledRule, sources []string) *matchHit {
	for _, sourceText := range sources {
		if sourceText == "" {
			continue
		}
		if hit := compiled.match(sourceText); hit != nil {
			return hit
		}
	}
	return nil
}

// matchFirstPath 对路径源逐条做 glob/正则匹配。
func matchFirstPath(compiled *compiledRule, sources []string) *matchHit {
	for _, pathValue := range sources {
		if pathValue == "" {
			continue
		}
		if hit := compiled.matchPath(pathValue); hit != nil {
			return hit
		}
	}
	return nil
}

// eventScanSources 按事件类型提取三类扫描源：
//   - commandSources：工具输入中的命令串（键 command）；
//   - pathSources：工具输入中的文件路径（键 file_path/notebook_path/path）；
//   - textSources：对话正文、工具结果摘要、工具输入整体 JSON。
//
// session_start 事件无业务文本，三类均为空。
func eventScanSources(event schema.Event) (commandSources []string, pathSources []string, textSources []string) {
	switch event.EventType {
	case schema.EventTypeConversation:
		textSources = append(textSources, event.Content)
	case schema.EventTypeToolResult:
		if event.ToolOutput != nil {
			textSources = append(textSources, event.ToolOutput.Summary)
		}
	case schema.EventTypeToolCall:
		if len(event.ToolInput) > 0 {
			var toolInputFields map[string]any
			if unmarshalErr := json.Unmarshal(event.ToolInput, &toolInputFields); unmarshalErr == nil {
				for _, commandKey := range []string{"command"} {
					if commandText, ok := toolInputFields[commandKey].(string); ok && commandText != "" {
						commandSources = append(commandSources, commandText)
					}
				}
				for _, pathKey := range []string{"file_path", "notebook_path", "path"} {
					if pathValue, ok := toolInputFields[pathKey].(string); ok && pathValue != "" {
						pathSources = append(pathSources, pathValue)
					}
				}
			}
			// 整体 JSON 兜底扫描：覆盖非结构化键中的敏感串
			textSources = append(textSources, string(event.ToolInput))
		}
	}
	return commandSources, pathSources, textSources
}
