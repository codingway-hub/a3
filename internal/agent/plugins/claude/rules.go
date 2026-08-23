package claude

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/codingway-hub/a3/pkg/schema"
)

// Rule 终端侧风险规则定义；BuiltinRules 与服务端 rules 种子为同源清单
// （ID/名称/类别/等级/动作一致），保证两端语义对齐。新增规则须双端同步。
type Rule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Category  string   `json:"category"`   // dlp|cmd|file|git
	Target    string   `json:"target"`     // any|command|path|content
	Patterns  []string `json:"patterns"`   // 正则（target=any/command/content）
	PathGlobs []string `json:"path_globs"` // glob（target=path，支持 ~ 前缀与裸文件名）
	Severity  string   `json:"severity"`
	Action    string   `json:"action"`
}

// BuiltinRules 内置预置规则（v1 共 14 条）。
var BuiltinRules = []Rule{
	{ID: "dlp.aws_access_key", Name: "AWS AccessKey 泄露", Category: "dlp", Target: "any",
		Patterns: []string{`\bAKIA[0-9A-Z]{16}\b`}, Severity: "high", Action: "block"},
	{ID: "dlp.aws_secret_key", Name: "AWS SecretKey 泄露", Category: "dlp", Target: "any",
		Patterns: []string{`(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`}, Severity: "high", Action: "block"},
	{ID: "dlp.private_key_block", Name: "私钥文件内容泄露", Category: "dlp", Target: "any",
		Patterns: []string{`-----BEGIN [A-Z ]*PRIVATE KEY-----`}, Severity: "high", Action: "block"},
	{ID: "dlp.generic_api_key", Name: "通用 API 密钥泄露", Category: "dlp", Target: "any",
		Patterns: []string{`(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*["']?[A-Za-z0-9_\-/.+]{16,}`},
		Severity: "high", Action: "block"},
	{ID: "dlp.jwt", Name: "JWT 令牌泄露", Category: "dlp", Target: "any",
		Patterns: []string{`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`},
		Severity: "high", Action: "block"},
	{ID: "dlp.db_conn_string", Name: "数据库连接串凭证泄露", Category: "dlp", Target: "any",
		Patterns: []string{`(?i)(postgres(?:ql)?|mysql|mongodb(\+srv)?|redis)://[^\s:@]+:[^\s@]+@`},
		Severity: "high", Action: "block"},
	{ID: "cmd.rm_rf_root", Name: "高危递归强删(rm -rf 根/家目录)", Category: "cmd", Target: "command",
		// r/f 旗标顺序任意（-rf / -fr），且目标以绝对路径、~ 或 * 开头
		Patterns: []string{`\brm\s+(?:-{1,2}[\w=-]+\s+)*(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\s+"?(?:/|~|\*)`},
		Severity: "high", Action: "block"},
	{ID: "cmd.git_force_push", Name: "Git 强制推送", Category: "git", Target: "command",
		Patterns: []string{`git\s+push[^|;&]*(--force\b|--force-with-lease|--delete\b)`}, Severity: "high", Action: "block"},
	{ID: "cmd.remote_script_exec", Name: "远程脚本管道执行", Category: "cmd", Target: "command",
		Patterns: []string{`(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z|da|)sh\b`}, Severity: "high", Action: "block"},
	{ID: "cmd.chmod_privilege", Name: "全权限放开(chmod 777 系统路径)", Category: "cmd", Target: "command",
		Patterns: []string{`chmod\s+(-R\s+)?[0-7]*7[0-7]*7\s+/`}, Severity: "high", Action: "block"},
	{ID: "cmd.disk_wipe", Name: "磁盘抹写/格式化", Category: "cmd", Target: "command",
		Patterns: []string{`(mkfs\.\w+\s|dd\s+if=[^ ]*\s+of=/dev/)`}, Severity: "high", Action: "block"},
	{ID: "file.ssh_private_read", Name: "敏感私钥文件访问", Category: "file", Target: "path",
		PathGlobs: []string{"~/.ssh/*", "*.pem", "id_rsa*"}, Severity: "high", Action: "block"},
	{ID: "file.dotenv_access", Name: "环境变量文件访问", Category: "file", Target: "path",
		PathGlobs: []string{".env", "*.env"}, Severity: "high", Action: "alert"},
	{ID: "git.history_rewrite", Name: "Git 历史重写", Category: "git", Target: "command",
		Patterns: []string{`git\s+(reset\s+--hard|filter-branch|filter-repo|rebase\s+--root)`},
		Severity: "medium", Action: "alert"},
}

// compiledRule 编译后的单条规则。
type compiledRule struct {
	definition Rule
	patterns   []*regexp.Regexp
	pathGlobs  []string
}

// RuleMatcher 终端侧规则引擎：对 Hook 输入做风险判定。
type RuleMatcher struct {
	compiledRules []*compiledRule
	homeDir       string
}

// NewRuleMatcher 编译内置规则构建匹配器；homeDir 用于 path 规则的 ~ 归一化。
func NewRuleMatcher(homeDir string) (*RuleMatcher, error) {
	ruleMatcher := &RuleMatcher{homeDir: homeDir}
	for _, ruleDefinition := range BuiltinRules {
		builtRule := &compiledRule{definition: ruleDefinition, pathGlobs: ruleDefinition.PathGlobs}
		for _, patternText := range ruleDefinition.Patterns {
			compiledPattern, compileErr := regexp.Compile(patternText)
			if compileErr != nil {
				return nil, fmt.Errorf("规则 %s 正则编译失败: %w", ruleDefinition.ID, compileErr)
			}
			builtRule.patterns = append(builtRule.patterns, compiledPattern)
		}
		if len(builtRule.patterns) == 0 && len(builtRule.pathGlobs) == 0 {
			return nil, fmt.Errorf("规则 %s 未定义任何模式", ruleDefinition.ID)
		}
		switch builtRule.definition.Target {
		case "any", "command", "path", "content":
		default:
			return nil, fmt.Errorf("规则 %s target 不合法: %q", ruleDefinition.ID, builtRule.definition.Target)
		}
		ruleMatcher.compiledRules = append(ruleMatcher.compiledRules, builtRule)
	}
	return ruleMatcher, nil
}

// EvaluateHookInput 对 Hook 工具输入做全量规则判定，返回命中的风险标签（每规则至多一个）。
// v1 规则不区分工具名，仅按输入内容判定；未来可扩展按 toolName 定向规则。
func (ruleMatcher *RuleMatcher) EvaluateHookInput(toolInput json.RawMessage) []schema.RiskTag {
	inputText := string(toolInput)
	commandSources, pathSources := extractToolInputSources(toolInput)

	var matchedTags []schema.RiskTag
	for _, builtRule := range ruleMatcher.compiledRules {
		var hitSnippet string
		found := false
		switch builtRule.definition.Target {
		case "command":
			for _, commandSource := range commandSources {
				if hitSnippet, found = matchFirstRegex(builtRule.patterns, commandSource); found {
					break
				}
			}
		case "path":
			// 路径候选 = 显式路径字段 + 命令文本中的空白分隔 token（覆盖 cat ~/.ssh/id_rsa 等场景）
			pathCandidates := append([]string{}, pathSources...)
			for _, commandSource := range commandSources {
				pathCandidates = append(pathCandidates, tokenizeCommand(commandSource)...)
			}
			hitSnippet, found = matchPathGlobs(builtRule.pathGlobs, pathCandidates, ruleMatcher.homeDir)
		case "content":
			if hitSnippet, found = matchFirstRegex(builtRule.patterns, inputText); !found {
				hitSnippet, found = matchFirstRegex(builtRule.patterns, strings.Join(commandSources, "\n"))
			}
		case "any":
			scanPool := append([]string{}, commandSources...)
			scanPool = append(scanPool, pathSources...)
			scanPool = append(scanPool, inputText)
			for _, scanSource := range scanPool {
				if hitSnippet, found = matchFirstRegex(builtRule.patterns, scanSource); found {
					break
				}
			}
			if !found {
				hitSnippet, found = matchPathGlobs(builtRule.pathGlobs, pathSources, ruleMatcher.homeDir)
			}
		}
		if found {
			matchedTags = append(matchedTags, buildRiskTag(builtRule.definition, hitSnippet))
		}
	}
	return matchedTags
}

// extractToolInputSources 从 tool_input 提取命令类与路径类扫描源。
func extractToolInputSources(toolInput json.RawMessage) (commandSources []string, pathSources []string) {
	if len(toolInput) == 0 {
		return nil, nil
	}
	var inputFields map[string]any
	if unmarshalErr := json.Unmarshal(toolInput, &inputFields); unmarshalErr != nil {
		return nil, nil
	}
	for fieldName, fieldValue := range inputFields {
		fieldText, isString := fieldValue.(string)
		if !isString {
			continue
		}
		switch fieldName {
		case "command":
			commandSources = append(commandSources, fieldText)
		case "file_path", "notebook_path", "path":
			pathSources = append(pathSources, fieldText)
		}
	}
	return commandSources, pathSources
}

// tokenizeCommand 将命令文本按空白与常见 shell 分隔符切词，供 path 类规则扫描。
func tokenizeCommand(commandText string) []string {
	return strings.FieldsFunc(commandText, func(sepRune rune) bool {
		switch sepRune {
		case ' ', '\t', '\n', '"', '\'', ';', '|', '&', '(', ')':
			return true
		}
		return false
	})
}

// matchFirstRegex 返回首个命中模式的上下文片段与是否命中。
func matchFirstRegex(patternList []*regexp.Regexp, sourceText string) (string, bool) {
	for _, compiledPattern := range patternList {
		if matchLocation := compiledPattern.FindStringIndex(sourceText); matchLocation != nil {
			return buildHitSnippet(sourceText, matchLocation[0], matchLocation[1]), true
		}
	}
	return "", false
}

// matchPathGlobs 对候选路径做三形态 glob 匹配：原值、~ 归一化、basename。
// 例：homeDir=/Users/liu 时 /Users/liu/.ssh/id_rsa 可命中 ~/.ssh/* 与 id_rsa*。
func matchPathGlobs(globList []string, pathCandidates []string, homeDirectory string) (string, bool) {
	for _, pathCandidate := range pathCandidates {
		globCandidates := []string{pathCandidate}
		if homeDirectory != "" && strings.HasPrefix(pathCandidate, homeDirectory+"/") {
			globCandidates = append(globCandidates, "~"+pathCandidate[len(homeDirectory):])
		}
		globCandidates = append(globCandidates, path.Base(pathCandidate))

		for _, globPattern := range globList {
			for _, globCandidate := range globCandidates {
				globMatched, matchErr := filepath.Match(globPattern, globCandidate)
				if matchErr == nil && globMatched {
					return buildHitSnippet(pathCandidate, 0, len(pathCandidate)), true
				}
			}
		}
	}
	return "", false
}

// snippetContextRunes 命中片段前后保留的上下文字符数。
const snippetContextRunes = 80

// maskedRunesUpperBound 命中内容脱敏后中间星号的最大长度上限。
const maskedRunesUpperBound = 6

// buildHitSnippet 取命中位置 ±80 rune 的窗口并脱敏命中部分（>8 字符保留首4尾2）。
func buildHitSnippet(sourceText string, hitBegin int, hitEnd int) string {
	sourceRunes := []rune(sourceText)
	byteOffsetOfRune := func(runeIndex int) int { return len(string(sourceRunes[:runeIndex])) }

	beginByte, endByte := byteOffsetOfRune(0), byteOffsetOfRune(len(sourceRunes))
	hitBeginRune := runeIndexOfByte(sourceRunes, hitBegin)
	hitEndRune := runeIndexOfByte(sourceRunes, hitEnd)

	windowBegin := hitBeginRune - snippetContextRunes
	if windowBegin < 0 {
		windowBegin = 0
	}
	windowEnd := hitEndRune + snippetContextRunes
	if windowEnd > len(sourceRunes) {
		windowEnd = len(sourceRunes)
	}
	beginByte = byteOffsetOfRune(windowBegin)
	endByte = byteOffsetOfRune(windowEnd)

	maskedHit := sourceText[hitBegin:hitEnd]
	if maskRunes := []rune(maskedHit); len(maskRunes) > 8 {
		maskedHit = string(maskRunes[:4]) + strings.Repeat("*", maskedRunesUpperBound) + string(maskRunes[len(maskRunes)-2:])
	}

	var snippetBuilder strings.Builder
	snippetBuilder.WriteString(sourceText[beginByte:hitBegin])
	snippetBuilder.WriteString(maskedHit)
	snippetBuilder.WriteString(sourceText[hitEnd:endByte])
	if windowBegin > 0 {
		return "…" + snippetBuilder.String()
	}
	return snippetBuilder.String()
}

// runeIndexOfByte 将字节下标转换为 rune 下标（越界时夹取边界）。
func runeIndexOfByte(sourceRunes []rune, byteIndex int) int {
	if byteIndex <= 0 {
		return 0
	}
	consumedBytes := 0
	for runeIndex, sourceRune := range sourceRunes {
		if consumedBytes >= byteIndex {
			return runeIndex
		}
		consumedBytes += len(string(sourceRune))
	}
	return len(sourceRunes)
}

// buildRiskTag 组装命中标签（Snippet 已脱敏）。
func buildRiskTag(ruleDefinition Rule, hitSnippet string) schema.RiskTag {
	return schema.RiskTag{
		Code:        ruleDefinition.ID,
		Name:        ruleDefinition.Name,
		Severity:    schema.Severity(ruleDefinition.Severity),
		Action:      schema.RiskAction(ruleDefinition.Action),
		MatchedRule: ruleDefinition.ID,
		Snippet:     hitSnippet,
	}
}
