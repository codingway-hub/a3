package masking

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskSecretKeepsHeadAndTail(t *testing.T) {
	testCases := []struct {
		name         string
		secretText   string
		expectedText string
	}{
		{"典型 AWS Key（AKIA+恰好16位）", "AKIAIOSFODNN7EXAMPLE", "AKIA…MPLE"},
		{"长 JWT 片段", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlMzQ1", "eyJh…MzQ1"},
		{"过短全打星-8字符", "abcd1234", "********"},
		{"过短全打星-9字符", "abcd12345", "abcd…2345"},
		{"含中文 rune 安全", "密钥甲乙丙丁戊己庚辛壬", "密钥甲乙…己庚辛壬"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expectedText, MaskSecret(testCase.secretText))
		})
	}
}

func TestRedactAllTableDriven(t *testing.T) {
	privateKeyBlock := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7vX9fakefakefake
-----END RSA PRIVATE KEY-----`

	testCases := []struct {
		name         string
		sourceText   string
		expectedText string
	}{
		{
			name:         "无敏感内容原样保留",
			sourceText:   "帮我修复登录页面的报错，谢谢",
			expectedText: "帮我修复登录页面的报错，谢谢",
		},
		{
			name:         "句中 AWS Key 掩码且上下文保留",
			sourceText:   "请用这个 key AKIAIOSFODNN7EXAMPLE 调用",
			expectedText: "请用这个 key AKIA…MPLE 调用",
		},
		{
			name:         "JWT 掩码",
			sourceText:   "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlMzQ1 结束",
			expectedText: "token=eyJh…MzQ1 结束",
		},
		{
			name:         "api_key 赋值掩码（键名+值整体掩码，尾引号保留）",
			sourceText:   "export API_KEY='sk-proj-abcdefgh1234567890ab'",
			expectedText: "export API_…90ab'",
		},
		{
			name:         "数据库连接串整体掩码",
			sourceText:   "postgres://admin:s3cr3t-pass@db.internal:5432/a3",
			expectedText: MaskSecret("postgres://admin:s3cr3t-pass@db.internal:5432/a3"),
		},
		{
			name:         "PEM 私钥整块替换",
			sourceText:   "配置如下\n" + privateKeyBlock + "\n结束",
			expectedText: "配置如下\n-----BEGIN PRIVATE KEY-----…(已脱敏)\n结束",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.expectedText, RedactAll(testCase.sourceText))
		})
	}
}

func TestRedactAllHandlesMultipleSecretsInOneText(t *testing.T) {
	mixedText := "AKIAIOSFODNN7EXAMPLE and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlMzQ1"
	maskedText := RedactAll(mixedText)
	assert.Contains(t, maskedText, "AKIA…MPLE")
	assert.Contains(t, maskedText, "eyJh…MzQ1")
	assert.NotContains(t, maskedText, "c2lnbmF0dXJl")
}
