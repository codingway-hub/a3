// Package config 读取服务端环境变量配置并提供合理缺省值。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config 是服务端运行配置。
type Config struct {
	Addr                   string // 监听地址
	DatabaseURL            string // PostgreSQL 连接串
	JWTSecret              string // 控制台 JWT 签名密钥
	JWTSecretGenerated     bool   // JWTSecret 是否为自动生成的（需日志警告提醒持久化）
	AdminUsername          string
	AdminPassword          string
	AdminPasswordGenerated bool
	AllowAutoRegister      bool   // 对应 A3_ALLOW_AUTO_REGISTER，默认关闭；单机自助接入需显式开启
	WebDist                string // 前端静态目录；空则不托管
	PublicURL              string // 对外公开地址 A3_PUBLIC_URL（反代场景配置即权威）；空则按请求 Host 推导
	AgentDist              string // 采集器发布产物目录 A3_AGENT_DIST；空则不提供下载与指南页产物提示
	NotifyWebhookURL       string // 告警外送 webhook 地址 A3_NOTIFY_WEBHOOK_URL；空则禁用外送
	NotifyWebhookFormat    string // webhook 信封格式 A3_NOTIFY_WEBHOOK_FORMAT：generic|wecom|dingtalk|feishu，默认 generic
	NotifyMinSeverity      string // 外送最低严重级别 A3_NOTIFY_MIN_SEVERITY：low|medium|high，空=全部
	TLSCertPath            string // 可选 HTTPS：A3_TLS_CERT；与 TLSKeyPath 必须同时提供
	TLSKeyPath             string // 可选 HTTPS：A3_TLS_KEY；与 TLSCertPath 必须同时提供
}

// Load 从环境变量加载配置；缺省值满足本地单机开发开箱即用。
func Load() (*Config, error) {
	serverConfig := &Config{
		Addr:                envOrDefault("A3_ADDR", "127.0.0.1:8080"), // 默认仅绑本机，避免明文意外暴露到局域网
		DatabaseURL:         envOrDefault("A3_DATABASE_URL", "postgres://a3:a3@127.0.0.1:5432/a3?sslmode=disable"),
		AdminUsername:       envOrDefault("A3_ADMIN_USER", "admin"),
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

	var err error
	serverConfig.AllowAutoRegister, err = strconv.ParseBool(envOrDefault("A3_ALLOW_AUTO_REGISTER", "false"))
	if err != nil {
		return nil, fmt.Errorf("A3_ALLOW_AUTO_REGISTER 不是合法布尔值: %w", err)
	}

	// JWT 密钥未配置时随机生成：重启后所有控制台会话失效（仅提示，不阻断）
	serverConfig.JWTSecret = os.Getenv("A3_JWT_SECRET")
	if serverConfig.JWTSecret == "" {
		generatedSecret, generateErr := randomHex(32)
		if generateErr != nil {
			return nil, fmt.Errorf("生成 JWT 密钥失败: %w", generateErr)
		}
		serverConfig.JWTSecret = generatedSecret
		serverConfig.JWTSecretGenerated = true
	}

	// 管理员口令未配置时同样随机生成并提示（首次启动可从日志获取）
	serverConfig.AdminPassword = os.Getenv("A3_ADMIN_PASSWORD")
	if serverConfig.AdminPassword == "" {
		generatedPassword, generateErr := randomHex(8)
		if generateErr != nil {
			return nil, fmt.Errorf("生成管理员口令失败: %w", generateErr)
		}
		serverConfig.AdminPassword = generatedPassword
		serverConfig.AdminPasswordGenerated = true
	}
	return serverConfig, nil
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
