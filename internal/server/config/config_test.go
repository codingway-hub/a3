package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unsetCoreEnv 清理可能从宿主环境泄漏的测试相关变量，保证用例读默认值；
// A3_SERVER_STATE_DIR 指向独立临时目录，避免 Load 自动落盘把用户真实主目录写脏。
func unsetCoreEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"A3_ADDR", "A3_TLS_CERT", "A3_TLS_KEY",
		"A3_JWT_SECRET", "A3_ADMIN_PASSWORD", "A3_AGENT_SIGNING_KEY",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("A3_SERVER_STATE_DIR", t.TempDir())
}

func TestLoadDefaultsToLoopback(t *testing.T) {
	unsetCoreEnv(t)
	serverConfig, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外失败: %v", err)
	}
	if serverConfig.Addr != "127.0.0.1:8080" {
		t.Errorf("A3_ADDR 默认应为 127.0.0.1:8080，得到 %q", serverConfig.Addr)
	}
	if serverConfig.TLSCertPath != "" || serverConfig.TLSKeyPath != "" {
		t.Error("未配置 TLS 时路径应为空")
	}
}

func TestLoadOverrides(t *testing.T) {
	unsetCoreEnv(t)
	t.Setenv("A3_ADDR", ":8080")
	serverConfig, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外失败: %v", err)
	}
	if serverConfig.Addr != ":8080" {
		t.Errorf("A3_ADDR 覆盖失效: %q", serverConfig.Addr)
	}
}

func TestLoadRejectsPartialTLS(t *testing.T) {
	unsetCoreEnv(t)
	t.Setenv("A3_TLS_CERT", "/path/to/cert.pem") // 只有 cert，无 key
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "A3_TLS_CERT 与 A3_TLS_KEY 必须同时配置") {
		t.Fatalf("仅配置证书应报错，得到: %v", err)
	}
}

func TestLoadAcceptsCompleteTLS(t *testing.T) {
	unsetCoreEnv(t)
	t.Setenv("A3_TLS_CERT", "/path/to/cert.pem")
	t.Setenv("A3_TLS_KEY", "/path/to/key.pem")
	serverConfig, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外失败: %v", err)
	}
	if serverConfig.TLSCertPath != "/path/to/cert.pem" || serverConfig.TLSKeyPath != "/path/to/key.pem" {
		t.Errorf("TLS 路径未透传: %+v", serverConfig)
	}
}

func TestLoadNotifyWebhookValidation(t *testing.T) {
	testCases := []struct {
		name        string
		webhookURL  string
		format      string
		minSeverity string
		expectError bool
	}{
		{"全空=禁用且合法", "", "", "", false},
		{"合法 URL 默认格式", "https://hooks.example.com/xyz", "", "", false},
		{"wecom 格式合法", "http://127.0.0.1:9999/hook", "wecom", "", false},
		{"feishu 格式合法", "http://127.0.0.1:9999/hook", "feishu", "", false},
		{"dingtalk 格式合法", "http://127.0.0.1:9999/hook", "dingtalk", "medium", false},
		{"非法 scheme 拒绝", "ftp://hooks.example.com", "", "", true},
		{"缺 host 拒绝", "http://", "", "", true},
		{"非 URL 拒绝", "::not-a-url::", "", "", true},
		{"未知 format 拒绝", "http://h.example.com", "slack-legacy", "", true},
		{"未知 severity 拒绝", "http://h.example.com", "", "critical", true},
		{"severity 大写归一合法", "http://h.example.com", "", "HIGH", false},
	}
	for _, testCase := range testCases {
		unsetCoreEnv(t)
		t.Setenv("A3_NOTIFY_WEBHOOK_URL", testCase.webhookURL)
		t.Setenv("A3_NOTIFY_WEBHOOK_FORMAT", testCase.format)
		t.Setenv("A3_NOTIFY_MIN_SEVERITY", testCase.minSeverity)
		loadedConfig, err := Load()
		if testCase.expectError && err == nil {
			t.Errorf("%s: 应拒绝启动", testCase.name)
		}
		if !testCase.expectError && err != nil {
			t.Errorf("%s: 意外失败: %v", testCase.name, err)
		}
		if !testCase.expectError && err == nil && testCase.format == "" {
			if loadedConfig.NotifyWebhookFormat != "generic" {
				t.Errorf("%s: 空 format 应回退 generic，得到 %q", testCase.name, loadedConfig.NotifyWebhookFormat)
			}
		}
	}
}

func TestNotifySeveritiesExpansion(t *testing.T) {
	testCases := []struct {
		minSeverity  string
		expectedSevs []string
	}{
		{"", []string{"low", "medium", "high"}},
		{"low", []string{"low", "medium", "high"}},
		{"medium", []string{"medium", "high"}},
		{"high", []string{"high"}},
	}
	for _, testCase := range testCases {
		severityConfig := &Config{NotifyMinSeverity: testCase.minSeverity}
		assert.ElementsMatch(t, testCase.expectedSevs, severityConfig.NotifySeverities(),
			"min_severity=%q 展开错误", testCase.minSeverity)
	}
}

func TestResolveStateDirDefaultsUnderHome(t *testing.T) {
	t.Setenv("A3_SERVER_STATE_DIR", "")
	stateDir, err := resolveStateDir()
	require.NoError(t, err)
	homeDir, homeErr := os.UserHomeDir()
	require.NoError(t, homeErr)
	assert.Equal(t, filepath.Join(homeDir, ".a3-server"), stateDir)
}

func TestResolveStateDirEnvOverridesDefault(t *testing.T) {
	t.Setenv("A3_SERVER_STATE_DIR", "/custom/state")
	stateDir, err := resolveStateDir()
	require.NoError(t, err)
	assert.Equal(t, "/custom/state", stateDir)
}

func TestJWTSecretPersistsAcrossLoads(t *testing.T) {
	unsetCoreEnv(t)
	stateDir := t.TempDir()
	t.Setenv("A3_SERVER_STATE_DIR", stateDir)

	firstConfig, firstErr := Load()
	require.NoError(t, firstErr)
	require.True(t, firstConfig.JWTSecretGenerated, "状态目录无密钥时应自动生成")
	assert.NotEmpty(t, firstConfig.JWTSecret)
	assert.Equal(t, filepath.Join(stateDir, "jwt-secret"), firstConfig.JWTSecretPath)

	secretFilePath := filepath.Join(stateDir, "jwt-secret")
	fileInfo, statErr := os.Stat(secretFilePath)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm(), "JWT 密钥文件权限应为 0600")

	secondConfig, secondErr := Load()
	require.NoError(t, secondErr)
	assert.Equal(t, firstConfig.JWTSecret, secondConfig.JWTSecret, "重启应复用持久化密钥，控制台登录态不掉")
	assert.False(t, secondConfig.JWTSecretGenerated, "复用已有密钥不应再标记生成本启动新密钥")
}

func TestExplicitJWTSecretPreventsFilePersistence(t *testing.T) {
	unsetCoreEnv(t)
	stateDir := t.TempDir()
	t.Setenv("A3_SERVER_STATE_DIR", stateDir)
	t.Setenv("A3_JWT_SECRET", "explicit-secret-abc")

	serverConfig, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "explicit-secret-abc", serverConfig.JWTSecret)
	assert.False(t, serverConfig.JWTSecretGenerated)
	assert.Equal(t, "", serverConfig.JWTSecretPath, "显式密钥时不应声称有持久化路径")

	_, statErr := os.Stat(filepath.Join(stateDir, "jwt-secret"))
	assert.True(t, errors.Is(statErr, os.ErrNotExist), "显式配置 A3_JWT_SECRET 时不得写入状态目录")
}

func TestJWTSecretFileReuseWithWhitespaceTolerance(t *testing.T) {
	unsetCoreEnv(t)
	stateDir := t.TempDir()
	t.Setenv("A3_SERVER_STATE_DIR", stateDir)
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "jwt-secret"), []byte("persisted-secret-1\n"), 0o600))

	serverConfig, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "persisted-secret-1", serverConfig.JWTSecret, "读取已有密钥应容忍结尾换行")
	assert.False(t, serverConfig.JWTSecretGenerated)
}

func TestAdminPasswordNeverAutoGenerated(t *testing.T) {
	unsetCoreEnv(t)
	t.Setenv("A3_ADMIN_PASSWORD", "")

	serverConfig, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "", serverConfig.AdminPassword, "口令不得自动生成，缺省为空（首启无口令由种子逻辑拒绝）")

	t.Setenv("A3_ADMIN_PASSWORD", "s3cret-123")
	serverConfig, err = Load()
	require.NoError(t, err)
	assert.Equal(t, "s3cret-123", serverConfig.AdminPassword, "显式口令应原样透传")
}

func TestSigningKeyPersistsAcrossLoads(t *testing.T) {
	unsetCoreEnv(t)
	stateDir := t.TempDir()
	t.Setenv("A3_SERVER_STATE_DIR", stateDir)

	firstConfig, firstErr := Load()
	require.NoError(t, firstErr)
	require.NotNil(t, firstConfig.SigningKey, "未显式配置时应自动生成发布签名密钥")
	require.True(t, firstConfig.SigningKeyGenerated)
	assert.NotEmpty(t, firstConfig.SigningKey.Public())
	assert.Equal(t, filepath.Join(stateDir, "agent-signing-key"), firstConfig.SigningKeyPath)

	keyFilePath := filepath.Join(stateDir, "agent-signing-key")
	fileInfo, statErr := os.Stat(keyFilePath)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm(), "签名密钥文件权限应为 0600")

	secondConfig, secondErr := Load()
	require.NoError(t, secondErr)
	require.NotNil(t, secondConfig.SigningKey)
	assert.Equal(t, firstConfig.SigningKey.Public(), secondConfig.SigningKey.Public(),
		"重启应复用持久化私钥（种子一致 → 公钥一致），产物签名稳定")
	assert.False(t, secondConfig.SigningKeyGenerated)
}

func TestExplicitSigningKeyPreventsFilePersistence(t *testing.T) {
	unsetCoreEnv(t)
	stateDir := t.TempDir()
	t.Setenv("A3_SERVER_STATE_DIR", stateDir)
	t.Setenv("A3_AGENT_SIGNING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)))

	serverConfig, err := Load()
	require.NoError(t, err)
	require.NotNil(t, serverConfig.SigningKey)
	assert.Equal(t, string(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)), string(serverConfig.SigningKey.Seed()))
	assert.False(t, serverConfig.SigningKeyGenerated)
	assert.Equal(t, "", serverConfig.SigningKeyPath, "显式密钥时不应声称有持久化路径")

	_, statErr := os.Stat(filepath.Join(stateDir, "agent-signing-key"))
	assert.True(t, errors.Is(statErr, os.ErrNotExist), "显式配置 A3_AGENT_SIGNING_KEY 时不得写入状态目录")
}

func TestExplicitSigningKeyRejectsMalformedSeed(t *testing.T) {
	unsetCoreEnv(t)
	for _, invalidSeed := range []string{"not-base64!!", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 16))} {
		t.Setenv("A3_AGENT_SIGNING_KEY", invalidSeed)
		_, err := Load()
		require.Error(t, err, "非法 seed %q 应拒绝启动（fail-closed，拒绝静默回滚到自动生成）", invalidSeed)
	}
}
