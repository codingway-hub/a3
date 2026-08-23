// Package masking 提供终端侧通用数据脱敏管道：对即将上报的文本做二次保护，
// 只保留命中证明所需的最小信息（密钥类仅显示前 4 后 4 字符，如 AKIA…X7FQ）。
package masking

import (
	"regexp"
	"strings"
)

// visibleEdgeRunes 掩码后两端各保留的字符数。
const visibleEdgeRunes = 4

// ellipsis 中间省略符。
const ellipsis = "…"

// privateKeyBlockPattern 匹配整段 PEM 私钥块（跨行）。
var privateKeyBlockPattern = regexp.MustCompile(
	`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

// secretLikePatterns 单行密钥形态：整体命中后按 MaskSecret 掩码替换。
var secretLikePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b`),
	regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']?[A-Za-z0-9_\-/.+]{16,}`),
	regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s/@]+@[^\s]+`),
}

// MaskSecret 对单个密钥文本做首尾保留掩码：前 4 后 4 可见、中间省略；
// 过短（≤2×visibleEdgeRunes）时全量打星，避免短串经掩码仍可完整还原。
func MaskSecret(secretText string) string {
	secretRunes := []rune(secretText)
	if len(secretRunes) <= visibleEdgeRunes*2 {
		return strings.Repeat("*", len(secretRunes))
	}
	return string(secretRunes[:visibleEdgeRunes]) + ellipsis + string(secretRunes[len(secretRunes)-visibleEdgeRunes:])
}

// RedactAll 扫描文本中常见密钥形态并就地掩码：
// PEM 私钥块整段替换；其余命中按 MaskSecret 保留首尾证据字符。非敏感文本原样返回。
func RedactAll(sourceText string) string {
	maskedText := privateKeyBlockPattern.ReplaceAllStringFunc(sourceText,
		func(blockMatch string) string {
			return "-----BEGIN PRIVATE KEY-----" + ellipsis + "(已脱敏)"
		})
	for _, secretPattern := range secretLikePatterns {
		maskedText = secretPattern.ReplaceAllStringFunc(maskedText, MaskSecret)
	}
	return maskedText
}
