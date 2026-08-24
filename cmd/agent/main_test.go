package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunAgentCLISubcommandDispatch(t *testing.T) {
	assert.Equal(t, 0, runAgentCLI([]string{"version"}))
	assert.Equal(t, 0, runAgentCLI([]string{"help"}))

	assert.Equal(t, 1, runAgentCLI(nil), "无子命令应报用法并失败")
	assert.Equal(t, 1, runAgentCLI([]string{"no-such-command"}), "未知子命令应失败")
	assert.Equal(t, 1, runAgentCLI([]string{"hook"}), "hook 缺子子命令应失败")
}

func TestIsLocalServerURL(t *testing.T) {
	testCases := []struct {
		serverURL   string
		expectLocal bool
	}{
		{"http://127.0.0.1:8080", true},
		{"http://localhost:8080", true},
		{"http://[::1]:8080", true},
		{"https://a3.example.com", false},
		{"http://192.168.1.10:8080", false},
		{"::not-a-url::", false},
	}
	for _, testCase := range testCases {
		assert.Equal(t, testCase.expectLocal, isLocalServerURL(testCase.serverURL),
			"server_url=%s", testCase.serverURL)
	}
}

func TestShortHostnameFrom(t *testing.T) {
	assert.Equal(t, "mbp", shortHostnameFrom("mbp.example.com"))
	assert.Equal(t, "mbp-local", shortHostnameFrom("mbp-local"))
	assert.Equal(t, "", shortHostnameFrom(""))
}

func TestMachineFingerprintStableAndDistinct(t *testing.T) {
	fingerprint := machineFingerprintOf("host-a", "darwin/arm64", "user-a")

	assert.Len(t, fingerprint, 64, "应为 sha256 十六进制")
	assert.Equal(t, fingerprint, machineFingerprintOf("host-a", "darwin/arm64", "user-a"),
		"同输入指纹必须稳定（注册幂等键）")

	assert.NotEqual(t, fingerprint, machineFingerprintOf("host-b", "darwin/arm64", "user-a"))
	assert.NotEqual(t, fingerprint, machineFingerprintOf("host-a", "linux/amd64", "user-a"))
	assert.NotEqual(t, fingerprint, machineFingerprintOf("host-a", "darwin/arm64", "user-b"))

	localFingerprint := buildMachineFingerprint()
	assert.Len(t, localFingerprint, 64, "真实环境指纹也应为 sha256 十六进制")
}
