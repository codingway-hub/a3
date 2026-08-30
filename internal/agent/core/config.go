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

// PluginAll 插件选择的特殊值：启用全部编译内置插件（见各插件包在装配处的构造函数表）。
const PluginAll = "all"

// Config 终端采集器运行配置；CLI flag 优先级高于环境变量，环境变量高于默认值。
type Config struct {
	ServerURL               string        // 服务端地址（http/https）
	DeviceToken             string        // 设备 Token（a3d_ 前缀）；空表示未注册，run 前需先 register
	SpoolDir                string        // 断网缓存队列目录
	StateDir                string        // 状态目录（offsets 等断点续传状态）
	SpoolMaxBytes           int64         // 断网缓存总容量上限（含在途租约）；0=默认 512MB
	SpoolQuarantineMaxBytes int64         // 断网缓存隔离区容量上限；0=默认 128MB
	BatchSize               int           // 单批上报事件数上限（1~500）
	FlushInterval           time.Duration // 批量化冲刷间隔
	MaskEnabled             bool          // 终端侧脱敏开关
	InsecureTLS             bool          // 跳过 TLS 证书校验（仅自签名单机部署场景使用）
	LogLevel                string        // 日志级别：debug|info|warn|error
	Plugins                 []string      // 启用的插件名列表；[all] 表示全部内置插件（默认）
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
		Plugins:       []string{PluginAll},
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
	if spoolMaxBytesText := getenv("A3_SPOOL_MAX_BYTES"); spoolMaxBytesText != "" {
		if spoolMaxBytes, parseErr := strconv.ParseInt(spoolMaxBytesText, 10, 64); parseErr == nil {
			config.SpoolMaxBytes = spoolMaxBytes
		}
	}
	if quarantineMaxBytesText := getenv("A3_SPOOL_QUARANTINE_MAX_BYTES"); quarantineMaxBytesText != "" {
		if quarantineMaxBytes, parseErr := strconv.ParseInt(quarantineMaxBytesText, 10, 64); parseErr == nil {
			config.SpoolQuarantineMaxBytes = quarantineMaxBytes
		}
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
	if pluginsText := getenv("A3_PLUGINS"); pluginsText != "" {
		// 只做词法归一不做语义校验：非法值原样进入 Plugins，由 Validate 启动时报错——
		// 采集范围选择配错了应当启动即失败，而非静默回退默认值扩大采集范围
		config.Plugins = ParsePluginSelection(pluginsText)
	}

	// 环境变量未指定服务端地址时，回退读 register 持久化的 server-url
	// （install.sh 一条命令安装后，run/常驻服务进程不依赖环境变量即可找到服务端）
	if config.ServerURL == "" {
		config.ServerURL = LoadPersistedServerURL(config.StateDir)
	}
}

// serverURLFileName register 成功后持久化服务端地址的文件名（StateDir 下）。
const serverURLFileName = "server-url"

// LoadPersistedServerURL 读取 StateDir 下 register 持久化的服务端地址；
// 文件缺失/为空/含空白时返回空串，调用方继续走原校验路径报错。
func LoadPersistedServerURL(stateDir string) string {
	rawBytes, readErr := os.ReadFile(filepath.Join(stateDir, serverURLFileName))
	if readErr != nil {
		return ""
	}
	return strings.TrimSpace(string(rawBytes))
}

// ParsePluginSelection 把逗号分隔的插件选择文本归一化：去首尾空白、丢弃空项、转小写。
// 合法性（名称形状、all 混用限制）由 Config.Validate 统一收口。
func ParsePluginSelection(selectionText string) []string {
	textParts := strings.Split(selectionText, ",")
	selectedPlugins := make([]string, 0, len(textParts))
	for _, textPart := range textParts {
		normalizedPart := strings.ToLower(strings.TrimSpace(textPart))
		if normalizedPart != "" {
			selectedPlugins = append(selectedPlugins, normalizedPart)
		}
	}
	return selectedPlugins
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
	if config.SpoolMaxBytes < 0 {
		return fmt.Errorf("spool_max_bytes 不能为负: %d（0 表示默认 512MB）", config.SpoolMaxBytes)
	}
	if config.SpoolQuarantineMaxBytes < 0 {
		return fmt.Errorf("spool_quarantine_max_bytes 不能为负: %d（0 表示默认 128MB）", config.SpoolQuarantineMaxBytes)
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
	if len(config.Plugins) == 0 {
		return fmt.Errorf("plugins 选择不能为空（逗号分隔的插件名，或 %s）", PluginAll)
	}
	for _, pluginName := range config.Plugins {
		switch {
		case pluginName == PluginAll:
			if len(config.Plugins) > 1 {
				return fmt.Errorf("plugins=%s 不能与其他插件名混用", PluginAll)
			}
		case isValidPluginName(pluginName):
		default:
			return fmt.Errorf("plugins 含不合法的插件名 %q（允许小写字母/数字/连字符，或 %s）",
				pluginName, PluginAll)
		}
	}
	return nil
}

// isValidPluginName 插件名词法校验：仅允许小写字母、数字与连字符。
func isValidPluginName(pluginName string) bool {
	if pluginName == "" {
		return false
	}
	for _, charRune := range pluginName {
		isLowerLetter := charRune >= 'a' && charRune <= 'z'
		isDigit := charRune >= '0' && charRune <= '9'
		if !isLowerLetter && !isDigit && charRune != '-' {
			return false
		}
	}
	return true
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
