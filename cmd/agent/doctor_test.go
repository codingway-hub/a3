package main

import (
	"bytes"
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