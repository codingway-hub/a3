package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/agent/core"
)

// testDoctorConfig 构造沙箱医生的基线配置：home/StateDir/SpoolDir 全落 t.TempDir，
// 并解除环境变量对插件监听目录/规则快照的干扰，保证判定确定性。
func testDoctorConfig(t *testing.T, homeDir string) core.Config {
	t.Helper()
	t.Setenv("A3_STATE_DIR", "")
	t.Setenv("CODEX_HOME", "")
	agentConfig := core.Default(homeDir)
	agentConfig.ServerURL = "http://127.0.0.1:1"
	return agentConfig
}

// storeIdentity 在安全目录写入完整设备身份（device-token + device-id）。
func storeIdentity(t *testing.T, stateDirectory string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(stateDirectory, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stateDirectory, "device-token"), []byte("a3d_test\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(stateDirectory, "device-id"), []byte("device-test\n"), 0o600))
}

func TestRunDoctorAllGreenWithWarnings(t *testing.T) {
	homeDir := t.TempDir()
	agentConfig := testDoctorConfig(t, homeDir)
	storeIdentity(t, agentConfig.StateDir)

	var outputBuffer bytes.Buffer
	exitCode := runDoctor(homeDir, agentConfig, &outputBuffer, false)

	assert.Equal(t, 0, exitCode, "身份完整时自检应通过（监听目录/Hook/服务缺失仅警告）")
	outputText := outputBuffer.String()
	for _, requiredMarker := range []string{"[通过] 版本", "[通过] 配置", "[通过] 设备身份", "[通过] 断网缓存"} {
		assert.Contains(t, outputText, requiredMarker)
	}
	assert.NotContains(t, outputText, "[失败]", "不应出现任何失败级问题")
	assert.Contains(t, outputText, "跳过服务端连通性探测（测试/非交互模式）", "runExternal=false 应跳过网络探测")
	assert.Contains(t, outputText, "自检结果：通过")
}

func TestRunDoctorMissingIdentityFails(t *testing.T) {
	homeDir := t.TempDir()
	agentConfig := testDoctorConfig(t, homeDir)

	var outputBuffer bytes.Buffer
	exitCode := runDoctor(homeDir, agentConfig, &outputBuffer, false)

	assert.Equal(t, 2, exitCode, "未登记应判为失败")
	outputText := outputBuffer.String()
	assert.Contains(t, outputText, "[失败] 设备身份")
	assert.Contains(t, outputText, "register --server", "应给出登记指引")
}

func TestRunDoctorInvalidServerURLFails(t *testing.T) {
	homeDir := t.TempDir()
	agentConfig := testDoctorConfig(t, homeDir)
	agentConfig.ServerURL = "not-a-url"

	var outputBuffer bytes.Buffer
	exitCode := runDoctor(homeDir, agentConfig, &outputBuffer, false)

	assert.Equal(t, 2, exitCode)
	assert.Contains(t, outputBuffer.String(), "[失败] 配置")
	assert.Contains(t, outputBuffer.String(), "a3-agent register --server", "空/非法服务端地址应提示登记")
}

func TestRunDoctorSpoolUnwritableFails(t *testing.T) {
	homeDir := t.TempDir()
	agentConfig := testDoctorConfig(t, homeDir)
	storeIdentity(t, agentConfig.StateDir)
	blockerFile := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blockerFile, []byte("x"), 0o600))
	// 把 SpoolDir 挂到普通文件之下：MkdirAll 必然失败，断网缓存不可用应判失败
	agentConfig.SpoolDir = filepath.Join(blockerFile, "spool")

	var outputBuffer bytes.Buffer
	exitCode := runDoctor(homeDir, agentConfig, &outputBuffer, false)

	assert.Equal(t, 2, exitCode)
	assert.Contains(t, outputBuffer.String(), "[失败] 断网缓存")
}

// installAgentSignatureLayout 复刻 install.sh 安装期落盘：二进制 + 配套签名 + PEM 公钥
// （DER-base64 + fold 64 列 + BEGIN/END 围栏，与模板的 printf|fold 重建一致）。
func installAgentSignatureLayout(t *testing.T, homeDir string, binBytes []byte) ed25519.PublicKey {
	t.Helper()
	publicKey, privateKey, generateErr := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, generateErr)

	binDir := filepath.Join(homeDir, ".a3", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "a3-agent"), binBytes, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "a3-agent.sig"),
		ed25519.Sign(privateKey, binBytes), 0o600))

	pubDER, derErr := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, derErr)
	foldedLines := foldBase64Lines(base64.StdEncoding.EncodeToString(pubDER))
	pemText := "-----BEGIN PUBLIC KEY-----\n" + foldedLines + "\n-----END PUBLIC KEY-----\n"
	require.NoError(t, os.MkdirAll(filepath.Join(homeDir, ".a3"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(homeDir, ".a3", "agent-pubkey.pem"), []byte(pemText), 0o600))
	return publicKey
}

// foldBase64Lines 按 64 列折叠 base64（等价 sh 的 fold -w 64，最后一行不带尾换行）。
func foldBase64Lines(text string) string {
	var folded string
	for len(text) > 64 {
		folded += text[:64] + "\n"
		text = text[64:]
	}
	return folded + text
}

func TestRunDoctorSignaturePass(t *testing.T) {
	homeDir := t.TempDir()
	agentConfig := testDoctorConfig(t, homeDir)
	storeIdentity(t, agentConfig.StateDir)

	binBytes := []byte("final-agent-binary-bytes")
	installAgentSignatureLayout(t, homeDir, binBytes)

	var outputBuffer bytes.Buffer
	exitCode := runDoctor(homeDir, agentConfig, &outputBuffer, false)

	assert.Equal(t, 0, exitCode, "签名一致时自检应通过")
	outputText := outputBuffer.String()
	assert.Contains(t, outputText, "[通过] 发布签名")
	assert.Contains(t, outputText, "与发布签名一致")
	assert.Contains(t, outputText, "指纹:", "应给出公钥指纹供与服务端核对")
}

func TestRunDoctorSignatureTamperedFails(t *testing.T) {
	homeDir := t.TempDir()
	agentConfig := testDoctorConfig(t, homeDir)
	storeIdentity(t, agentConfig.StateDir)
	installAgentSignatureLayout(t, homeDir, []byte("original-binary"))

	// 篡改安装字节（未重新发布）→ 自检必须硬失败
	require.NoError(t, os.WriteFile(filepath.Join(homeDir, ".a3", "bin", "a3-agent"), []byte("tampered!"), 0o755))

	var outputBuffer bytes.Buffer
	exitCode := runDoctor(homeDir, agentConfig, &outputBuffer, false)

	assert.Equal(t, 2, exitCode, "发布签名不匹配必须判失败并退出 2")
	assert.Contains(t, outputBuffer.String(), "[失败] 发布签名")
	assert.Contains(t, outputBuffer.String(), "不匹配", "应指出字节与签名不符")
}

func TestRunDoctorSignatureLayoutMissingSkips(t *testing.T) {
	homeDir := t.TempDir()
	agentConfig := testDoctorConfig(t, homeDir)
	storeIdentity(t, agentConfig.StateDir)
	// 不装任何签名布局：pre-P2 存量安装情形
	var outputBuffer bytes.Buffer
	exitCode := runDoctor(homeDir, agentConfig, &outputBuffer, false)

	assert.Equal(t, 0, exitCode, "无签名布局应 [跳过] 而非判失败，不推高退出码")
	assert.Contains(t, outputBuffer.String(), "[跳过] 发布签名")
}

func TestRunDoctorReportsRollbackAvailable(t *testing.T) {
	homeDir := t.TempDir()
	agentConfig := testDoctorConfig(t, homeDir)
	storeIdentity(t, agentConfig.StateDir)

	binDir := filepath.Join(homeDir, ".a3", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "a3-agent.prev"), []byte("legacy-prev"), 0o755))

	var outputBuffer bytes.Buffer
	exitCode := runDoctor(homeDir, agentConfig, &outputBuffer, false)

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, outputBuffer.String(), "[信息]", "可回滚属提示信息")
	assert.Contains(t, outputBuffer.String(), "上一版本已保留")
	assert.Contains(t, outputBuffer.String(), "a3-agent rollback")
}