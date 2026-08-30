package config

import (
	"strings"
	"testing"
)

// unsetCoreEnv 清理可能从宿主环境泄漏的测试相关变量，保证用例读默认值。
func unsetCoreEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"A3_ADDR", "A3_ALLOW_AUTO_REGISTER", "A3_TLS_CERT", "A3_TLS_KEY",
		"A3_JWT_SECRET", "A3_ADMIN_PASSWORD",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadDefaultsToLoopbackAndNoAutoRegister(t *testing.T) {
	unsetCoreEnv(t)
	serverConfig, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外失败: %v", err)
	}
	if serverConfig.Addr != "127.0.0.1:8080" {
		t.Errorf("A3_ADDR 默认应为 127.0.0.1:8080，得到 %q", serverConfig.Addr)
	}
	if serverConfig.AllowAutoRegister {
		t.Error("A3_ALLOW_AUTO_REGISTER 默认应为 false")
	}
	if serverConfig.TLSCertPath != "" || serverConfig.TLSKeyPath != "" {
		t.Error("未配置 TLS 时路径应为空")
	}
}

func TestLoadOverrides(t *testing.T) {
	unsetCoreEnv(t)
	t.Setenv("A3_ADDR", ":8080")
	t.Setenv("A3_ALLOW_AUTO_REGISTER", "true")
	serverConfig, err := Load()
	if err != nil {
		t.Fatalf("Load() 意外失败: %v", err)
	}
	if serverConfig.Addr != ":8080" {
		t.Errorf("A3_ADDR 覆盖失效: %q", serverConfig.Addr)
	}
	if !serverConfig.AllowAutoRegister {
		t.Error("A3_ALLOW_AUTO_REGISTER=true 覆盖失效")
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

func TestLoadRejectsInvalidAutoRegister(t *testing.T) {
	unsetCoreEnv(t)
	t.Setenv("A3_ALLOW_AUTO_REGISTER", "not-a-bool")
	if _, err := Load(); err == nil {
		t.Fatal("非法 A3_ALLOW_AUTO_REGISTER 应报错")
	}
}