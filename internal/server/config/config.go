// Package config 读取服务端环境变量配置并提供合理缺省值。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// 服务端持久状态目录与 JWT 密钥文件名。
// 状态目录存重启不掉的登录态签名密钥等凭据：目录 0700、密钥文件 0600。
// 注意不与客户端 A3_STATE_DIR（默认 ~/.a3）混用，避免身份/密钥状态目录互相串味。
const (
	defaultStateDirName = ".a3-server"
	jwtSecretFileName   = "jwt-secret"
)

// Config 是服务端运行配置。
type Config struct {
	Addr                string // 监听地址
	DatabaseURL         string // PostgreSQL 连接串
	JWTSecret           string // 控制台 JWT 签名密钥
	JWTSecretGenerated  bool   // JWTSecret 是否为本启动新建并落盘（需日志提示持久化路径）
	JWTSecretPath       string // JWT 密钥持久化路径（显式 A3_JWT_SECRET 时为空）
	AdminUsername       string
	AdminPassword       string // 管理员种子口令（仅账号表为空的首启生效；显式提供，绝不自动生成）
	StateDir            string // 服务端持久状态目录 A3_SERVER_STATE_DIR；默认 ~/.a3-server
	WebDist             string // 前端静态目录；空则不托管
	PublicURL           string // 对外公开地址 A3_PUBLIC_URL（反代场景配置即权威）；空则按请求 Host 推导
	AgentDist           string // 采集器发布产物目录 A3_AGENT_DIST；空则不提供下载与指南页产物提示
	NotifyWebhookURL    string // 告警外送 webhook 地址 A3_NOTIFY_WEBHOOK_URL；空则禁用外送
	NotifyWebhookFormat string // webhook 信封格式 A3_NOTIFY_WEBHOOK_FORMAT：generic|wecom|dingtalk|feishu，默认 generic
	NotifyMinSeverity   string // 外送最低严重级别 A3_NOTIFY_MIN_SEVERITY：low|medium|high，空=全部
	TLSCertPath         string // 可选 HTTPS：A3_TLS_CERT；与 TLSKeyPath 必须同时提供
	TLSKeyPath          string // 可选 HTTPS：A3_TLS_KEY；与 TLSCertPath 必须同时提供
}

// Load 从环境变量加载配置；缺省值满足本地单机开发开箱即用。
func Load() (*Config, error) {
	serverConfig := &Config{
		Addr:                envOrDefault("A3_ADDR", "127.0.0.1:8080"), // 默认仅绑本机，避免明文意外暴露到局域网
		DatabaseURL:         envOrDefault("A3_DATABASE_URL", "postgres://a3:a3@127.0.0.1:5432/a3?sslmode=disable"),
		AdminUsername:       envOrDefault("A3_ADMIN_USER", "admin"),
		AdminPassword:       os.Getenv("A3_ADMIN_PASSWORD"),
		WebDist:             os.Getenv("A3_WEB_DIST"),
		PublicURL:           strings.TrimSpace(os.Getenv("A3_PUBLIC_URL")),
		AgentDist:           strings.TrimSpace(os.Getenv("A3_AGENT_DIST")),
		NotifyWebhookURL:    strings.TrimSpace(os.Getenv("A3_NOTIFY_WEBHOOK_URL")),
		NotifyWebhookFormat: strings.TrimSpace(os.Getenv("A3_NOTIFY_WEBHOOK_FORMAT")),
		NotifyMinSeverity:   strings.ToLower(strings.TrimSpace(os.Getenv("A3_NOTIFY_MIN_SEVERITY"))),
		TLSCertPath:         os.Getenv("A3_TLS_CERT"),
		TLSKeyPath:          os.Getenv("A3_TLS_KEY"),
	}
	if (serverConfig.TLSCertPath == "") != (serverConfig.TLSKeyPath == "") {
		return nil, fmt.Errorf("A3_TLS_CERT 与 A3_TLS_KEY 必须同时配置才能启用 HTTPS")
	}

	// 告警外送配置校验：给了 URL 就必须是合法 http(s) 地址；枚举值非法直接拒绝启动
	if serverConfig.NotifyWebhookURL != "" {
		notifyURL, notifyURLErr := url.Parse(serverConfig.NotifyWebhookURL)
		if notifyURLErr != nil ||
			(notifyURL.Scheme != "http" && notifyURL.Scheme != "https") || notifyURL.Host == "" {
			return nil, fmt.Errorf("A3_NOTIFY_WEBHOOK_URL 不是合法的 http(s) 地址: %q", serverConfig.NotifyWebhookURL)
		}
	}
	if serverConfig.NotifyWebhookFormat == "" {
		serverConfig.NotifyWebhookFormat = "generic"
	}
	switch serverConfig.NotifyWebhookFormat {
	case "generic", "wecom", "dingtalk", "feishu":
	default:
		return nil, fmt.Errorf("A3_NOTIFY_WEBHOOK_FORMAT 非法值 %q（合法值：generic、wecom、dingtalk、feishu）",
			serverConfig.NotifyWebhookFormat)
	}
	switch serverConfig.NotifyMinSeverity {
	case "", "low", "medium", "high":
	default:
		return nil, fmt.Errorf("A3_NOTIFY_MIN_SEVERITY 非法值 %q（合法值：low、medium、high）",
			serverConfig.NotifyMinSeverity)
	}

	// 服务端持久状态目录：存登录态签名密钥等重启不掉的凭据；目录 0700、密钥文件 0600
	stateDir, stateDirErr := resolveStateDir()
	if stateDirErr != nil {
		return nil, stateDirErr
	}
	serverConfig.StateDir = stateDir

	// JWT 签名密钥：显式 A3_JWT_SECRET 最优先；留空则从状态目录复用/新建并原子落盘 0600，
	// 重启后控制台登录态稳定保持——不再每次启动随机一把导致全部会话失效。
	if explicitSecret := strings.TrimSpace(os.Getenv("A3_JWT_SECRET")); explicitSecret != "" {
		serverConfig.JWTSecret = explicitSecret
	} else {
		persistedSecret, secretPath, generated, secretErr := loadOrCreateJWTSecret(stateDir)
		if secretErr != nil {
			return nil, secretErr
		}
		serverConfig.JWTSecret = persistedSecret
		serverConfig.JWTSecretPath = secretPath
		serverConfig.JWTSecretGenerated = generated
	}

	// 管理员口令只读环境变量、绝不自动生成：口令一旦随机进日志即等于泄密；
	// 首启且账号表为空时必须在 main 显式提供（见 seedAdminUser 空口令报错）。
	return serverConfig, nil
}

// resolveStateDir 解析服务端持久状态目录：A3_SERVER_STATE_DIR 为空时回退用户主目录下 .a3-server。
func resolveStateDir() (string, error) {
	if configuredDir := os.Getenv("A3_SERVER_STATE_DIR"); configuredDir != "" {
		return configuredDir, nil
	}
	homeDir, homeErr := os.UserHomeDir()
	if homeErr != nil {
		return "", fmt.Errorf("解析服务端状态目录失败（A3_SERVER_STATE_DIR 未设置且取不到用户主目录）: %w", homeErr)
	}
	return filepath.Join(homeDir, defaultStateDirName), nil
}

// loadOrCreateJWTSecret 返回 JWT 签名密钥、落盘路径与本启动是否新建。
// 已持久化且非空的密钥直接复用（重启会话保持）；文件缺失/为空则生成 32 字节 hex 并原子落盘 0600。
func loadOrCreateJWTSecret(stateDir string) (secret string, secretPath string, generated bool, err error) {
	secretPath = filepath.Join(stateDir, jwtSecretFileName)
	if persistedSecret, readErr := os.ReadFile(secretPath); readErr == nil {
		if trimmedSecret := strings.TrimSpace(string(persistedSecret)); trimmedSecret != "" {
			return trimmedSecret, secretPath, false, nil
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", "", false, fmt.Errorf("读取持久化 JWT 密钥失败: %w", readErr)
	}

	generatedSecret, generateErr := randomHex(32)
	if generateErr != nil {
		return "", "", false, fmt.Errorf("生成 JWT 密钥失败: %w", generateErr)
	}
	if writeErr := writeJWTSecret(secretPath, generatedSecret); writeErr != nil {
		return "", "", false, writeErr
	}
	return generatedSecret, secretPath, true, nil
}

// writeJWTSecret 原子落盘 JWT 密钥并收紧权限：临时文件+改名，目录 0700、文件 0600。
func writeJWTSecret(secretPath string, secret string) error {
	stateDir := filepath.Dir(secretPath)
	if mkdirErr := os.MkdirAll(stateDir, 0o700); mkdirErr != nil {
		return fmt.Errorf("创建服务端状态目录失败: %w", mkdirErr)
	}
	tempFile, createErr := os.CreateTemp(stateDir, ".jwt-secret-*.tmp")
	if createErr != nil {
		return fmt.Errorf("创建 JWT 密钥临时文件失败: %w", createErr)
	}
	tempName := tempFile.Name()
	if _, writeErr := tempFile.WriteString(secret); writeErr != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempName)
		return fmt.Errorf("写入 JWT 密钥临时文件失败: %w", writeErr)
	}
	if closeErr := tempFile.Close(); closeErr != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("关闭 JWT 密钥临时文件失败: %w", closeErr)
	}
	if chmodErr := os.Chmod(tempName, 0o600); chmodErr != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("收紧 JWT 密钥文件权限失败: %w", chmodErr)
	}
	if renameErr := os.Rename(tempName, secretPath); renameErr != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("持久化 JWT 密钥失败: %w", renameErr)
	}
	return nil
}

// NotifySeverities 把外送最低严重级别展开为允许外送的 severity 集合，
// 供通知 worker 直接传给 store.ListUnnotifiedAlerts（该查询要求集合非空）。
func (serverConfig *Config) NotifySeverities() []string {
	switch serverConfig.NotifyMinSeverity {
	case "high":
		return []string{"high"}
	case "medium":
		return []string{"medium", "high"}
	default: // 空/low：全部（当前告警实际只产生 medium+，low 保留全集语义）
		return []string{"low", "medium", "high"}
	}
}

func envOrDefault(name string, defaultValue string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return defaultValue
}

func randomHex(byteLength int) (string, error) {
	randomBytes := make([]byte, byteLength)
	if _, readErr := rand.Read(randomBytes); readErr != nil {
		return "", readErr
	}
	return hex.EncodeToString(randomBytes), nil
}
