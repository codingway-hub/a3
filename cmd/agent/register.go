package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/internal/agent/core/spool"
	"github.com/codingway-hub/a3/internal/agent/core/transport"
	"github.com/codingway-hub/a3/internal/agent/plugins/claude"
)

// 设备身份持久化文件名。
const (
	deviceTokenFileName = "device-token"
	deviceIDFileName    = "device-id"
)

// resolveDeviceIdentity 依次尝试：CLI/env Token → 本地状态文件 → 单机自动注册。
// 返回 (token, deviceID, error)。
func resolveDeviceIdentity(ctx context.Context, agentConfig core.Config, logger *slog.Logger) (string, string, error) {
	if agentConfig.DeviceToken != "" {
		return agentConfig.DeviceToken, readStoredDeviceID(agentConfig.StateDir), nil
	}
	storedToken := readStoredDeviceToken(agentConfig.StateDir)
	if storedToken != "" {
		return storedToken, readStoredDeviceID(agentConfig.StateDir), nil
	}

	// 无 Token：仅本地地址允许自动注册（单机模式），分布式部署要求显式 register
	if !isLocalServerURL(agentConfig.ServerURL) {
		return "", "", fmt.Errorf(
			"缺少设备 Token：请先执行 a3-agent register --server %s 完成注册（远程服务端不自动注册）",
			agentConfig.ServerURL)
	}
	logger.Info("检测到本地服务端且无 Token，执行单机自动注册")
	uploaderClient, uploaderErr := transport.NewUploader(
		agentConfig.ServerURL, "", agentVersion, agentConfig.InsecureTLS, logger)
	if uploaderErr != nil {
		return "", "", uploaderErr
	}
	machineFingerprint := buildMachineFingerprint()
	registrationResult, registerErr := uploaderClient.RegisterDevice(ctx, transport.DeviceInfo{
		Hostname: shortHostname(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		MachineFingerprint: machineFingerprint,
	})
	if registerErr != nil {
		return "", "", fmt.Errorf("自动注册失败: %w", registerErr)
	}
	if storeErr := storeDeviceIdentity(agentConfig.StateDir,
		registrationResult.Token, registrationResult.DeviceID); storeErr != nil {
		logger.Warn("设备身份写盘失败(本次运行仍可用)",
			slog.String("error", storeErr.Error()))
	}
	logger.Info("自动注册完成", slog.String("device_id", registrationResult.DeviceID))
	return registrationResult.Token, registrationResult.DeviceID, nil
}

// registerCommand 显式注册子命令（分布式部署模式）。
func registerCommand(flagArguments []string) int {
	registerFlags := flag.NewFlagSet("register", flag.ContinueOnError)
	serverURL := registerFlags.String("server", os.Getenv("A3_SERVER_URL"), "服务端地址")
	insecureTLS := registerFlags.Bool("insecure-skip-tls-verify", false, "跳过 TLS 证书校验")
	if parseErr := registerFlags.Parse(flagArguments); parseErr != nil {
		fmt.Fprintln(os.Stderr, parseErr)
		return 1
	}
	if *serverURL == "" {
		fmt.Fprintln(os.Stderr, "必须提供 --server 或 A3_SERVER_URL")
		return 1
	}

	homeDir, homeErr := core.ResolveHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}
	stateDir := filepath.Join(homeDir, ".a3")

	uploaderClient, uploaderErr := transport.NewUploader(*serverURL, "", agentVersion, *insecureTLS, nil)
	if uploaderErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", uploaderErr)
		return 1
	}
	ctxWithTimeout, cancelTimeout := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelTimeout()

	fingerprint := buildMachineFingerprint()
	registrationResult, registerErr := uploaderClient.RegisterDevice(ctxWithTimeout, transport.DeviceInfo{
		Hostname: shortHostname(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		MachineFingerprint: fingerprint,
	})
	if registerErr != nil {
		fmt.Fprintf(os.Stderr, "注册失败: %v\n", registerErr)
		return 1
	}
	if storeErr := storeDeviceIdentity(stateDir, registrationResult.Token, registrationResult.DeviceID); storeErr != nil {
		fmt.Fprintf(os.Stderr, "保存身份失败: %v\n", storeErr)
		return 1
	}
	fmt.Printf("✅ 注册成功\ndevice_id = %s\ntoken     = %s（已保存至 %s）\n",
		registrationResult.DeviceID, registrationResult.Token,
		filepath.Join(stateDir, deviceTokenFileName))
	return 0
}

// hookCommand PreToolUse Hook 入口：读 stdin 裁决；alert 风险事件直接入断网缓存队列。
func hookCommand(flagArguments []string) int {
	agentConfig, loadErr := loadAgentConfig(flagArguments)
	if loadErr != nil {
		// Hook 场景绝不因自身配置问题阻断用户工作流：退回默认配置继续裁决，
		// 最坏情况只是没有上报目标（风险事件仍落本地缓存，run 恢复后补报）
		homeDir, homeErr := core.ResolveHomeDir()
		if homeErr != nil {
			return 0 // 连主目录都无法定位：彻底静默放行
		}
		agentConfig = core.Default(homeDir)
		agentConfig.ApplyEnv(os.Getenv)
	}
	spoolQueue, spoolErr := spool.New(agentConfig.SpoolDir, 0)
	if spoolErr != nil {
		fmt.Fprintf(os.Stderr, "a3 hook 缓存不可用，已放行: %v\n", spoolErr)
		return 0
	}
	claudePlugin, pluginErr := claude.NewPlugin(mustHomeDirOrEmpty())
	if pluginErr != nil {
		fmt.Fprintf(os.Stderr, "a3 hook 插件加载失败，已放行: %v\n", pluginErr)
		return 0
	}
	return claudePlugin.RunPreToolUse(os.Stdin, os.Stderr,
		func(envelopeBytes []byte) {
			if enqueueErr := spoolQueue.Enqueue(envelopeBytes); enqueueErr != nil {
				fmt.Fprintf(os.Stderr, "a3 hook 风险事件缓存失败: %v\n", enqueueErr)
			}
		}, agentVersion)
}

// installHookCommand / uninstallHookCommand Hook 装卸子命令。
func installHookCommand() int {
	homeDir, homeErr := core.ResolveHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}
	claudePlugin, pluginErr := claude.NewPlugin(homeDir)
	if pluginErr != nil {
		fmt.Fprintf(os.Stderr, "插件加载失败: %v\n", pluginErr)
		return 1
	}
	changed, configureErr := claudePlugin.ConfigureHook(homeDir, true)
	if configureErr != nil {
		fmt.Fprintf(os.Stderr, "安装失败: %v\n", configureErr)
		return 1
	}
	if changed {
		fmt.Println("✅ 已安装 PreToolUse Hook 到 ~/.claude/settings.json（原配置已备份）")
	} else {
		fmt.Println("ℹ️ Hook 已存在，无需重复安装")
	}
	return 0
}

func uninstallHookCommand() int {
	homeDir, homeErr := core.ResolveHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}
	claudePlugin, pluginErr := claude.NewPlugin(homeDir)
	if pluginErr != nil {
		fmt.Fprintf(os.Stderr, "插件加载失败: %v\n", pluginErr)
		return 1
	}
	changed, configureErr := claudePlugin.ConfigureHook(homeDir, false)
	if configureErr != nil {
		fmt.Fprintf(os.Stderr, "卸载失败: %v\n", configureErr)
		return 1
	}
	if changed {
		fmt.Println("✅ 已从 ~/.claude/settings.json 移除 a3 Hook")
	} else {
		fmt.Println("ℹ️ 未发现已安装的 a3 Hook")
	}
	return 0
}

// ---- 设备身份与指纹辅助 ----

// buildMachineFingerprint 构造机器指纹（hostname+os/arch+用户名 的 sha256），
// 作为注册幂等键；v1 采用轻量启发式，跨重装稳定即可。
func buildMachineFingerprint() string {
	hostName, _ := os.Hostname()
	currentUser, _ := user.Current()
	userName := ""
	if currentUser != nil {
		userName = currentUser.Username
	}
	return machineFingerprintOf(hostName, runtime.GOOS+"/"+runtime.GOARCH, userName)
}

// machineFingerprintOf 指纹计算的纯函数部分（可测）。
func machineFingerprintOf(hostName string, platformInfo string, userName string) string {
	digest := sha256.Sum256([]byte(hostName + "|" + platformInfo + "|" + userName))
	return hex.EncodeToString(digest[:])
}

// shortHostname 返回去掉域后缀的主机名。
func shortHostname() string {
	hostName, _ := os.Hostname()
	return shortHostnameFrom(hostName)
}

// shortHostnameFrom 主机名裁剪的纯函数部分（可测）。
func shortHostnameFrom(hostName string) string {
	for index, charRune := range hostName {
		if charRune == '.' {
			return hostName[:index]
		}
	}
	return hostName
}

// isLocalServerURL 判断服务端是否为本机地址（决定是否允许自动注册）。
func isLocalServerURL(serverURLText string) bool {
	parsedURL, parseErr := url.Parse(serverURLText)
	if parseErr != nil {
		return false
	}
	switch parsedURL.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// readStoredDeviceToken / readStoredDeviceID / storeDeviceIdentity 状态目录读写。
func storedFilePath(stateDirectory string, fileName string) string {
	return filepath.Join(stateDirectory, fileName)
}

func readStoredDeviceToken(stateDirectory string) string {
	tokenBytes, _ := os.ReadFile(storedFilePath(stateDirectory, deviceTokenFileName))
	return strings.TrimSpace(string(tokenBytes))
}

func readStoredDeviceID(stateDirectory string) string {
	idBytes, _ := os.ReadFile(storedFilePath(stateDirectory, deviceIDFileName))
	return strings.TrimSpace(string(idBytes))
}

func storeDeviceIdentity(stateDirectory string, deviceTokenValue string, deviceIDValue string) error {
	if mkdirErr := os.MkdirAll(stateDirectory, 0o700); mkdirErr != nil {
		return mkdirErr
	}
	if writeErr := os.WriteFile(storedFilePath(stateDirectory, deviceTokenFileName),
		[]byte(deviceTokenValue+"\n"), 0o600); writeErr != nil {
		return writeErr
	}
	return os.WriteFile(storedFilePath(stateDirectory, deviceIDFileName),
		[]byte(deviceIDValue+"\n"), 0o600)
}

// mustHomeDirOrEmpty 主目录解析失败时返回空串（插件内部对空主目录有兜底行为，
// 且 hook 场景失败只应降级、不应阻断宿主工具）。
func mustHomeDirOrEmpty() string {
	homeDir, _ := core.ResolveHomeDir()
	return homeDir
}
