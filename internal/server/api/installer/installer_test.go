package installer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderInjectsServerURL(t *testing.T) {
	scriptText, renderErr := RenderInstallScript("http://aa.bb.com:12345")
	require.NoError(t, renderErr)

	assert.Contains(t, scriptText, `SERVER_URL="http://aa.bb.com:12345"`)
	// 模板占位符必须全部被替换，不残留
	assert.NotContains(t, scriptText, "{{.ServerURL}}")
	assert.True(t, strings.HasPrefix(scriptText, "#!/bin/sh"), "产物必须是可直接执行的 shell 脚本")
}

func TestRenderRejectsInvalidBaseURL(t *testing.T) {
	for _, invalidURL := range []string{
		"",
		"aa.bb.com:12345",       // 缺 scheme
		"ftp://aa.bb.com",       // 非法 scheme
		"http://",               // 缺 host
		"http://host extra/dir", // 解析失败
	} {
		_, renderErr := RenderInstallScript(invalidURL)
		assert.Error(t, renderErr, "地址 %q 应被拒绝", invalidURL)
	}
}

func TestAssetNameForWhitelist(t *testing.T) {
	assert.Equal(t, "a3-agent-darwin-amd64", AssetNameFor("darwin", "amd64"))
	assert.Equal(t, "a3-agent-darwin-arm64", AssetNameFor("darwin", "arm64"))
	assert.Equal(t, "a3-agent-linux-amd64", AssetNameFor("linux", "amd64"))
	assert.Equal(t, "a3-agent-linux-arm64", AssetNameFor("linux", "arm64"))
	assert.Equal(t, "a3-agent-windows-amd64.exe", AssetNameFor("windows", "amd64"))
	assert.Equal(t, "", AssetNameFor("linux", "386"), "白名单外平台返回空")
	assert.Equal(t, "", AssetNameFor("freebsd", "amd64"))
}

func TestSupportedAssetNamesMatchesWhitelist(t *testing.T) {
	supportedNames := SupportedAssetNames()
	assert.Len(t, supportedNames, 5)
	for _, supportedName := range supportedNames {
		assert.Contains(t, supportedName, "a3-agent-")
	}
}
