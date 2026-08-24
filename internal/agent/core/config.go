// Package core 是终端采集器通用基座：配置、文件监听、断网缓存、传输、脱敏与插件挂载。
// 所有 Agent 差异化能力下沉至插件（见 plugins/），Core 不感知具体工具。
package core

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 服务端单批事件数硬上限（与服务端 ingest 校验一致，超限会被整批拒绝）。
const MaxBatchEvents = 500

// Config 终端采集器运行配置；CLI flag 优先级高于环境变量，环境变量高于默认值。
type Config struct {
	ServerURL     string        // 服务端地址（http/https）
	DeviceToken   string        // 设备 Token（a3d_ 前缀）；空表示未注册，run 时按策略自动注册
	SpoolDir      string        // 断网缓存队列目录
	StateDir      string        // 状态目录（offsets.json 等断点续传状态）
	BatchSize     int           // 单批上报事件数上限（1~500）
	FlushInterval time.Duration // 批量化冲刷间隔
	MaskEnabled   bool          // 终端侧脱敏开关
	InsecureTLS   bool          // 跳过 TLS 证书校验（仅自签名单机部署场景使用）
	LogLevel      string        // 日志级别：debug|info|warn|error
}

// Default 返回基于用户主目录推导的默认配置。
func Default(homeDir string) Config {
	stateDir := filepath.Join(homeDir, ".a3")
	return Config{
		ServerURL:     "",
		DeviceToken:   "",
		SpoolDir:      filepath.Join(stateDir, "spool"),
		StateDir:      stateDir,
		BatchSize:     200,
		FlushInterval: 2 * time.Second,
		MaskEnabled:   true,
		InsecureTLS:   false,
		LogLevel:      "info",
	}
}

// ApplyEnv 将环境变量叠加到当前配置上（仅覆盖已设置的项）。
func (config *Config) ApplyEnv(getenv func(string) string) {
	if serverURL := getenv("A3_SERVER_URL"); serverURL != "" {
		config.ServerURL = serverURL
	}
	if deviceToken := getenv("A3_DEVICE_TOKEN"); deviceToken != "" {
		config.DeviceToken = deviceToken
	}
	if spoolDir := getenv("A3_SPOOL_DIR"); spoolDir != "" {
		config.SpoolDir = spoolDir
	}
	if stateDir := getenv("A3_STATE_DIR"); stateDir != "" {
		config.StateDir = stateDir
	}
	if batchSizeText := getenv("A3_BATCH_SIZE"); batchSizeText != "" {
		if batchSize, parseErr := strconv.Atoi(batchSizeText); parseErr == nil {
			config.BatchSize = batchSize
		}
	}
	if flushIntervalText := getenv("A3_FLUSH_INTERVAL"); flushIntervalText != "" {
		if flushSeconds, parseErr := strconv.Atoi(flushIntervalText); parseErr == nil && flushSeconds > 0 {
			config.FlushInterval = time.Duration(flushSeconds) * time.Second
		}
	}
	if maskText := getenv("A3_MASK_ENABLED"); maskText != "" {
		config.MaskEnabled = maskText != "false" && maskText != "0" && maskText != "no"
	}
	if insecureText := getenv("A3_INSECURE_SKIP_TLS_VERIFY"); insecureText != "" {
		config.InsecureTLS = insecureText == "true" || insecureText == "1" || insecureText == "yes"
	}
	if logLevel := getenv("A3_LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}
}

// Validate 校验配置合法性；返回描述具体问题的中文错误。
func (config Config) Validate() error {
	serverURL, parseErr := url.Parse(config.ServerURL)
	if config.ServerURL == "" || parseErr != nil || (serverURL.Scheme != "http" && serverURL.Scheme != "https") || serverURL.Host == "" {
		return fmt.Errorf("server_url 不合法: %q（需形如 http://host:port 或 https://host:port）", config.ServerURL)
	}
	if config.DeviceToken != "" && !strings.HasPrefix(config.DeviceToken, "a3d_") {
		return fmt.Errorf("device_token 格式不合法: 应以 a3d_ 前缀开头")
	}
	if config.SpoolDir == "" {
		return fmt.Errorf("spool_dir 不能为空")
	}
	if config.StateDir == "" {
		return fmt.Errorf("state_dir 不能为空")
	}
	if config.BatchSize < 1 || config.BatchSize > MaxBatchEvents {
		return fmt.Errorf("batch_size 超出范围: %d（允许 1~%d，超限服务端会整批拒绝）", config.BatchSize, MaxBatchEvents)
	}
	if config.FlushInterval < 100*time.Millisecond {
		return fmt.Errorf("flush_interval 过短: %s（至少 100ms，避免空转）", config.FlushInterval)
	}
	switch config.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level 不合法: %q（允许值: debug/info/warn/error）", config.LogLevel)
	}
	return nil
}

// NewLogger 按配置级别构建文本格式 slog Logger（输出 stderr）。
// 级别不合法时回退 info 并以 warn 提示。
func NewLogger(config Config) *slog.Logger {
	logLevel := slog.LevelInfo
	switch config.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
}

// ResolveHomeDir 解析当前用户主目录；失败时返回中文错误。
func ResolveHomeDir() (string, error) {
	homeDir, homeErr := os.UserHomeDir()
	if homeErr != nil || homeDir == "" {
		return "", fmt.Errorf("无法定位用户主目录: %w", homeErr)
	}
	return homeDir, nil
}
