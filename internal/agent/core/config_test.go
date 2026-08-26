package core

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultDerivesDirsUnderHome(t *testing.T) {
	config := Default("/Users/demo")

	assert.Equal(t, "/Users/demo/.a3/spool", config.SpoolDir)
	assert.Equal(t, "/Users/demo/.a3", config.StateDir)
	assert.Equal(t, 200, config.BatchSize)
	assert.Equal(t, 2*time.Second, config.FlushInterval)
	assert.True(t, config.MaskEnabled, "脱敏默认开启")
	assert.False(t, config.InsecureTLS)
	assert.Equal(t, "info", config.LogLevel)

	config.ServerURL = "http://127.0.0.1:8080" // ServerURL 需显式提供，其余默认值即合法
	assert.NoError(t, config.Validate(), "默认配置（补上 ServerURL 后）应合法")
}

func TestValidateRejectsInvalidValues(t *testing.T) {
	valid := Default("/Users/demo")
	valid.ServerURL = "https://a3.example.com:8443"
	require.NoError(t, valid.Validate())

	testCases := []struct {
		name       string
		mutate     func(config *Config)
		errorParts []string
	}{
		{"缺 ServerURL", func(config *Config) { config.ServerURL = "" }, []string{"server_url"}},
		{"ServerURL 缺 scheme", func(config *Config) { config.ServerURL = "a3.example.com" }, []string{"server_url"}},
		{"ServerURL 缺 host", func(config *Config) { config.ServerURL = "http://" }, []string{"server_url"}},
		{"Token 前缀错误", func(config *Config) { config.DeviceToken = "tok-123" }, []string{"device_token", "a3d_"}},
		{"SpoolDir 为空", func(config *Config) { config.SpoolDir = "" }, []string{"spool_dir"}},
		{"StateDir 为空", func(config *Config) { config.StateDir = "" }, []string{"state_dir"}},
		{"BatchSize 过小", func(config *Config) { config.BatchSize = 0 }, []string{"batch_size"}},
		{"BatchSize 超服务端上限", func(config *Config) { config.BatchSize = MaxBatchEvents + 1 }, []string{"batch_size", "500"}},
		{"FlushInterval 过短", func(config *Config) { config.FlushInterval = 10 * time.Millisecond }, []string{"flush_interval"}},
		{"日志级别不合法", func(config *Config) { config.LogLevel = "verbose" }, []string{"log_level"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			broken := valid
			testCase.mutate(&broken)
			validateErr := broken.Validate()
			require.Error(t, validateErr)
			for _, errorPart := range testCase.errorParts {
				assert.Contains(t, validateErr.Error(), errorPart)
			}
		})
	}
}

func TestApplyEnvOverridesOnlySetVariables(t *testing.T) {
	baseConfig := Default("/Users/demo")

	envMap := map[string]string{
		"A3_SERVER_URL":               "http://127.0.0.1:18080",
		"A3_DEVICE_TOKEN":             "a3d_abc123",
		"A3_BATCH_SIZE":               "50",
		"A3_FLUSH_INTERVAL":           "5",
		"A3_MASK_ENABLED":             "false",
		"A3_INSECURE_SKIP_TLS_VERIFY": "true",
		"A3_LOG_LEVEL":                "debug",
	}
	baseConfig.ApplyEnv(func(envName string) string { return envMap[envName] })

	assert.Equal(t, "http://127.0.0.1:18080", baseConfig.ServerURL)
	assert.Equal(t, "a3d_abc123", baseConfig.DeviceToken)
	assert.Equal(t, 50, baseConfig.BatchSize)
	assert.Equal(t, 5*time.Second, baseConfig.FlushInterval)
	assert.False(t, baseConfig.MaskEnabled)
	assert.True(t, baseConfig.InsecureTLS)
	assert.Equal(t, "debug", baseConfig.LogLevel)
	assert.NoError(t, baseConfig.Validate())
}

func TestApplyEnvIgnoresMalformedNumbers(t *testing.T) {
	config := Default("/Users/demo")
	config.ServerURL = "http://a3.local"

	config.ApplyEnv(func(envName string) string {
		if envName == "A3_BATCH_SIZE" {
			return "not-a-number"
		}
		if envName == "A3_FLUSH_INTERVAL" {
			return "-3"
		}
		return ""
	})

	assert.Equal(t, 200, config.BatchSize, "非法数字应保留默认值")
	assert.Equal(t, 2*time.Second, config.FlushInterval, "非正数间隔应保留默认值")
}

func TestPluginsSelectionAndValidation(t *testing.T) {
	// 默认值：all（全部内置插件）
	defaultConfig := Default("/Users/demo")
	assert.Equal(t, []string{PluginAll}, defaultConfig.Plugins)
	validConfig := defaultConfig
	validConfig.ServerURL = "http://127.0.0.1:8080"
	require.NoError(t, validConfig.Validate())

	// env 归一化：trim、去空项、小写归一
	envConfig := Default("/Users/demo")
	envConfig.ServerURL = "http://127.0.0.1:8080"
	envConfig.ApplyEnv(func(envName string) string {
		if envName == "A3_PLUGINS" {
			return " Claude-Code , codex ,"
		}
		return ""
	})
	assert.Equal(t, []string{"claude-code", "codex"}, envConfig.Plugins,
		"应归一化为小写并丢弃空项")
	require.NoError(t, envConfig.Validate())

	// all 与具名插件混用应被拒绝
	mixedConfig := validConfig
	mixedConfig.Plugins = []string{PluginAll, "claude-code"}
	mixedErr := mixedConfig.Validate()
	require.Error(t, mixedErr)
	assert.Contains(t, mixedErr.Error(), "不能与其他插件名混用")

	// 非法名称（大写/空格/下划线）应被拒绝
	badNameConfig := validConfig
	badNameConfig.Plugins = []string{"Claude Code"}
	badNameErr := badNameConfig.Validate()
	require.Error(t, badNameErr)
	assert.Contains(t, badNameErr.Error(), "不合法的插件名")

	// 空选择应被拒绝
	emptyConfig := validConfig
	emptyConfig.Plugins = nil
	emptyErr := emptyConfig.Validate()
	require.Error(t, emptyErr)
	assert.Contains(t, emptyErr.Error(), "plugins 选择不能为空")
}

func TestNewLoggerLevelMapping(t *testing.T) {
	debugLogger := NewLogger(Config{LogLevel: "debug"})
	require.NotNil(t, debugLogger)
	assert.True(t, debugLogger.Enabled(nil, slog.LevelDebug), "debug 级别 Logger 应放行 Debug 日志")

	infoLogger := NewLogger(Config{LogLevel: "info"})
	assert.False(t, infoLogger.Enabled(nil, slog.LevelDebug), "info 级别 Logger 应过滤 Debug 日志")
	assert.True(t, infoLogger.Enabled(nil, slog.LevelInfo))

	warnLogger := NewLogger(Config{LogLevel: "warn"}) // 未知名回退 info
	assert.False(t, warnLogger.Enabled(nil, slog.LevelInfo))
}
