package installer

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderInjectsServerURL(t *testing.T) {
	scriptText, renderErr := RenderInstallScript("http://aa.bb.com:12345", nil)
	require.NoError(t, renderErr)

	// 服务端地址经 shellQuote 单引号包裹安全注入（防含 ' / ` 的配置命令注入）
	assert.Contains(t, scriptText, `SERVER_URL='http://aa.bb.com:12345'`, "地址应以单引号包裹注入")
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
		_, renderErr := RenderInstallScript(invalidURL, nil)
		assert.Error(t, renderErr, "地址 %q 应被拒绝", invalidURL)
	}
}

func TestRenderShellQuotesServerURL(t *testing.T) {
	// 含单引号/命令替换的地址不得逃逸出赋值（先前的命令注入点）：
	// shellQuote 单引号包裹 + 内部单引号翻倍，$()/` 只能作为字面文本存在且不可执行。
	hostileURL := "https://a.example/'$(touch /tmp/pwned)'`"
	scriptText, renderErr := RenderInstallScript(hostileURL, nil)
	require.NoError(t, renderErr)

	assert.Contains(t, scriptText, "SERVER_URL='https://a.example/", "赋值必须以单引号立即包裹地址")
	assert.Contains(t, scriptText, `$(touch /tmp/pwned)`, "命令替换字面量保留（供核对在引号内）")
	assertPosixScriptValid(t, scriptText, "宿主地址含引号/命令替换")
}

func TestRenderCredentialDeliveryMarkers(t *testing.T) {
	scriptText, renderErr := RenderInstallScript("http://aa.bb.com:12345", nil)
	require.NoError(t, renderErr)

	// 身份探测：已登记短路「已在册」
	assert.Contains(t, scriptText, "device-token")
	assert.Contains(t, scriptText, "device-id")
	assert.Contains(t, scriptText, "已在册")
	// stdin 即终端：直接交给 register 交互读取
	assert.Contains(t, scriptText, "[ -t 0 ]")
	// 管道下凭据经 /dev/tty 读取、再经 stdin 喂给 register（凭据绝不进 argv）
	assert.Contains(t, scriptText, "/dev/tty")
	assert.Contains(t, scriptText, "stty -echo")
	assert.Contains(t, scriptText, `printf '%s\n' "$INSTALL_CODE" | "$AGENT_BIN" register --server "$SERVER_URL"`)
	// 无 tty 时给出可执行的指引
	assert.Contains(t, scriptText, "curl $SERVER_URL/install.sh -o /tmp/a3-install.sh")
	// 总结与验证命令统一指向 doctor（渲染产物为 shell 源码，引号以 \" 转义呈现）
	assert.Contains(t, scriptText, `\"$AGENT_BIN\" doctor`)
}

func testSignKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	publicKey, _, generateErr := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, generateErr)
	return publicKey
}

func TestRenderSignedModeEmbedsPubkeyAndVerify(t *testing.T) {
	publicKey := testSignKey(t)
	scriptText, renderErr := RenderInstallScript("http://aa.bb.com:12345", publicKey)
	require.NoError(t, renderErr)

	// 公钥 DER-base64 与指纹注入
	assert.Contains(t, scriptText, "SIGN_PUBKEY_B64=")
	assert.Contains(t, scriptText, "SIGN_FINGERPRINT=")
	assert.NotContains(t, scriptText, "签名校验已禁用", "签名态不应输出禁用警告")
	// 验签分支与降级分支成型
	assert.Contains(t, scriptText, "openssl pkeyutl -verify -pubin -inkey")
	assert.Contains(t, scriptText, "-rawin -in")
	assert.Contains(t, scriptText, "SIG_CAPABLE")
	assert.Contains(t, scriptText, "服务端发布指纹")
	// 公钥必须是真的 ed25519 公钥（32 字节 base64 前后各含确定前缀）
	assert.Contains(t, scriptText, "-----BEGIN PUBLIC KEY-----")
	assert.Contains(t, scriptText, "-----END PUBLIC KEY-----")
}

func TestRenderNoSignKeyDegrades(t *testing.T) {
	scriptText, renderErr := RenderInstallScript("http://aa.bb.com:12345", nil)
	require.NoError(t, renderErr)

	assert.Contains(t, scriptText, "签名校验已禁用", "未配置签名密钥时应显式警示而非静默")
	assert.NotContains(t, scriptText, "SIGN_PUBKEY_B64=", "无签名态不应注入公钥")
}

func TestRenderedScriptSyntaxValid(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		signPub  ed25519.PublicKey
	}{
		{"签名态", testSignKey(t)},
		{"无签名态", nil},
	} {
		scriptText, renderErr := RenderInstallScript("http://aa.bb.com:12345", testCase.signPub)
		require.NoError(t, renderErr, testCase.name)
		assertPosixScriptValid(t, scriptText, testCase.name)
	}
}

// assertPosixScriptValid 渲染产物经 sh -n 校验语法（生效解释器为 POSIX sh / dash / bash）。
func assertPosixScriptValid(t *testing.T, scriptText string, caseName string) {
	t.Helper()
	scriptPath := filepath.Join(t.TempDir(), "install.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte(scriptText), 0o600))

	for _, shellPath := range []string{"/bin/sh", "dash", "bash"} {
		syntaxCheck := exec.Command(shellPath, "-n", scriptPath)
		if output, runErr := syntaxCheck.CombinedOutput(); runErr != nil {
			t.Fatalf("%s: %s -n 语法检查失败: %v\n%s", caseName, shellPath, runErr, output)
		}
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