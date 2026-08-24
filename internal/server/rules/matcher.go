package rules

import (
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/codingway-hub/a3/pkg/schema"
)

// snippetContextRunes 命中片段前后保留的上下文字符数。
const snippetContextRunes = 80

// compiledRule 是编译后的规则：正则预编译、glob 预展开，供引擎热路径复用。
type compiledRule struct {
	rule      Rule
	patterns  []*regexp.Regexp
	pathGlobs []string
	homeDir   string // 终端主目录，用于 ~/.ssh/* 形态 glob 的归一化匹配
}

// compileRule 编译单条规则；任一正则非法即报错（种子规则受迁移与测试双重保障）。
func compileRule(rule Rule, homeDir string) (*compiledRule, error) {
	compiled := &compiledRule{rule: rule, pathGlobs: rule.PathGlobs, homeDir: homeDir}
	for _, patternText := range rule.Patterns {
		compiledPattern, compileErr := regexp.Compile(patternText)
		if compileErr != nil {
			return nil, compileErr
		}
		compiled.patterns = append(compiled.patterns, compiledPattern)
	}
	return compiled, nil
}

// match 返回规则在给定源串上的首个命中；无命中返回 nil。
func (compiled *compiledRule) match(sourceText string) *matchHit {
	for _, compiledPattern := range compiled.patterns {
		if located := compiledPattern.FindStringIndex(sourceText); located != nil {
			return newSnippetHit(sourceText, located[0], located[1])
		}
	}
	return nil
}

// matchPath 用 glob（优先）与正则匹配单个路径串。
// 终端上报的路径是绝对路径，而种子 glob 常写作 ~/.ssh/*、id_rsa* 形态，
// 因此依次尝试三种候选形态：原值、$HOME→~ 归一化值、文件名基名。
func (compiled *compiledRule) matchPath(pathValue string) *matchHit {
	candidatePaths := []string{pathValue}
	if compiled.homeDir != "" {
		if trimmedPath, hasPrefix := strings.CutPrefix(pathValue, compiled.homeDir+"/"); hasPrefix {
			candidatePaths = append(candidatePaths, "~/"+trimmedPath)
		}
	}
	candidatePaths = append(candidatePaths, path.Base(pathValue))

	for _, globPattern := range compiled.pathGlobs {
		for _, candidatePath := range candidatePaths {
			if pathGlobMatch(globPattern, candidatePath) {
				return newSnippetHit(pathValue, 0, len(pathValue))
			}
		}
	}
	return compiled.match(pathValue)
}

// matchHit 描述一次命中：脱敏后的命中内容 + 带上下文的片段。
type matchHit struct {
	snippet       string
	maskedContent string
}

// newSnippetHit 截取命中位置前后 80 字符的上下文片段，并把命中文本本身脱敏——
// 审计后台展示的是片段而非原文，避免密钥等敏感内容二次泄露。
func newSnippetHit(sourceText string, matchStart int, matchEnd int) *matchHit {
	sourceRunes := []rune(sourceText)
	// 字节下标转 rune 下标，保证中文等多字节文本窗口正确
	startRune := utf8.RuneCountInString(sourceText[:matchStart])
	endRune := startRune + utf8.RuneCountInString(sourceText[matchStart:matchEnd])

	windowBegin := startRune - snippetContextRunes
	if windowBegin < 0 {
		windowBegin = 0
	}
	windowEnd := endRune + snippetContextRunes
	if windowEnd > len(sourceRunes) {
		windowEnd = len(sourceRunes)
	}

	var snippet strings.Builder
	if windowBegin > 0 {
		snippet.WriteString("…")
	}
	snippet.WriteString(string(maskedRunes(sourceRunes, windowBegin, windowEnd, startRune, endRune)))
	if windowEnd < len(sourceRunes) {
		snippet.WriteString("…")
	}

	return &matchHit{
		snippet:       snippet.String(),
		maskedContent: maskRunes(string(sourceRunes[startRune:endRune])),
	}
}

// maskedRunes 输出 [begin,end) 窗口文本，其中命中区间 [hitBegin,hitEnd) 以脱敏形态写入。
// 调用方保证 begin≤hitBegin≤hitEnd≤end。
func maskedRunes(sourceRunes []rune, begin int, end int, hitBegin int, hitEnd int) []rune {
	windowRunes := make([]rune, 0, end-begin)
	windowRunes = append(windowRunes, sourceRunes[begin:hitBegin]...)
	windowRunes = append(windowRunes, []rune(maskRunes(string(sourceRunes[hitBegin:hitEnd])))...)
	windowRunes = append(windowRunes, sourceRunes[hitEnd:end]...)
	return windowRunes
}

// maskRunes 脱敏命中文本：超过 8 字符保留前 4 后 2，中间以固定 6 个 * 替代；
// 短命中整体替换为等长 *。
func maskRunes(matchedText string) string {
	matchedRunes := []rune(matchedText)
	if len(matchedRunes) <= 8 {
		return strings.Repeat("*", len(matchedRunes))
	}
	return string(matchedRunes[:4]) + strings.Repeat("*", 6) + string(matchedRunes[len(matchedRunes)-2:])
}

// pathGlobMatch 做 glob 匹配：以 ** 结尾或含 ** 时退化为前缀/包含判断，
// 其余交给标准库 path.Match（* 不跨目录分隔符，符合路径语义）。
func pathGlobMatch(globPattern string, pathValue string) bool {
	if strings.HasSuffix(globPattern, "**") {
		prefix := strings.TrimSuffix(globPattern, "**")
		return strings.HasPrefix(pathValue, prefix)
	}
	matched, matchErr := path.Match(globPattern, pathValue)
	if matchErr != nil {
		return false // 非法 glob 视为不命中，不影响其余规则
	}
	return matched
}

// riskTag 把命中转换为标准风险标签（snippet 已脱敏）。
func (compiled *compiledRule) riskTag(hit *matchHit) schema.RiskTag {
	return schema.RiskTag{
		Code:        compiled.rule.ID,
		Name:        compiled.rule.Name,
		Severity:    compiled.rule.Severity,
		Action:      compiled.rule.Action,
		MatchedRule: compiled.rule.ID,
		Snippet:     hit.snippet,
	}
}
