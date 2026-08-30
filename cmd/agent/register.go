package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	"github.com/codingway-hub/a3/pkg/schema"
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
		explicitTokenDeviceID := readStoredDeviceID(agentConfig.StateDir)
		if explicitTokenDeviceID == "" {
			// 有 Token 无 device-id：服务端将拒绝归属校验(400→整批丢弃)，
			// 与其静默丢数不如启动即失败，提示补齐身份
			return "", "", fmt.Errorf(
				"已显式提供 Token 但缺少设备身份文件(%s)：请重新执行 a3-agent register 完成登记",
				filepath.Join(agentConfig.StateDir, deviceIDFileName))
		}
		return agentConfig.DeviceToken, explicitTokenDeviceID, nil
	}
	storedToken := readStoredDeviceToken(agentConfig.StateDir)
	if storedToken != "" {
		storedIdentityDeviceID := readStoredDeviceID(agentConfig.StateDir)
		if storedIdentityDeviceID == "" {
			return "", "", fmt.Errorf(
				"本地 Token 缺少配套的设备身份文件(%s)：请重新执行 a3-agent register 完成登记",
				filepath.Join(agentConfig.StateDir, deviceIDFileName))
		}
		return storedToken, storedIdentityDeviceID, nil
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
	// 本地无 Token 的自动注册不带凭证；服务端若已存在同指纹 active 设备会回 409
	// （本地 Token 丢失场景），据此给出吊销/恢复指引而不是反复重试。
	registrationResult, registerErr := uploaderClient.RegisterDevice(ctx, transport.DeviceInfo{
		Hostname: shortHostname(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		MachineFingerprint: machineFingerprint,
	}, "")
	if registerErr != nil {
		var rejectedErr *transport.NonRetryableError
		if errors.As(registerErr, &rejectedErr) && rejectedErr.StatusCode == http.StatusConflict {
			return "", "", fmt.Errorf(
				"自动注册被拒：本机指纹已登记但本地无凭证（Token 已丢失？）。\n"+
					"恢复路径：管理员在控制台吊销该设备后，重新执行 a3-agent register 即可重新上号")
		}
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
	// 重复注册必须携带既有 Token 作为凭证证明（同指纹只认凭证、不认指纹换发）
	credentialToken := readStoredDeviceToken(stateDir)
	registrationResult, registerErr := uploaderClient.RegisterDevice(ctxWithTimeout, transport.DeviceInfo{
		Hostname: shortHostname(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		MachineFingerprint: fingerprint,
	}, credentialToken)
	if registerErr != nil {
		if credentialToken == "" {
			var rejectedErr *transport.NonRetryableError
			if errors.As(registerErr, &rejectedErr) && rejectedErr.StatusCode == http.StatusConflict {
				fmt.Fprintf(os.Stderr,
					"注册失败：本机指纹已登记且需携带既有 Token 换发。\n"+
						"本机未找到 Token（%s 不存在或已清空）。\n"+
						"请恢复该文件后重试，或联系管理员在控制台吊销该设备后重新注册。\n",
					storedFilePath(stateDir, deviceTokenFileName))
				return 1
			}
		}
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
// 目标插件取自紧随子命令的首个位置参数或 --plugin 标记（缺省 claude-code，
// 兼容一期 settings.json 的无尾参条目）；任何装配异常一律放行（Hook 场景绝不阻断用户工作流）。
func hookCommand(flagArguments []string) int {
	targetPluginNames, remainingArguments := extractHookPluginTargets(flagArguments)
	agentConfig, loadErr := loadAgentConfig(remainingArguments)
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
	spoolQueue, spoolErr := spool.NewWithLimits(agentConfig.SpoolDir,
		agentConfig.SpoolMaxBytes, agentConfig.SpoolQuarantineMaxBytes)
	if spoolErr != nil {
		fmt.Fprintf(os.Stderr, "a3 hook 缓存不可用，已放行: %v\n", spoolErr)
		return 0
	}
	pluginRegistry, registryErr := buildRegistry(targetPluginNames, mustHomeDirOrEmpty())
	if registryErr != nil || len(pluginRegistry.All()) == 0 {
		fmt.Fprintf(os.Stderr, "a3 hook 目标插件不可用(%v)，已放行\n", registryErr)
		return 0
	}
	hookPlugin := pluginRegistry.All()[0]
	if len(targetPluginNames) > 1 {
		fmt.Fprintf(os.Stderr, "a3 hook 单进程仅裁决一个插件，使用 %s\n", hookPlugin.Name())
	}
	return runPreToolUseCLI(hookPlugin, os.Stdin, os.Stderr,
		func(envelopeBytes []byte) {
			if enqueueErr := spoolQueue.Enqueue(envelopeBytes); enqueueErr != nil {
				fmt.Fprintf(os.Stderr, "a3 hook 风险事件缓存失败: %v\n", enqueueErr)
			}
		}, agentVersion)
}

// runPreToolUseCLI 通用 PreToolUse CLI 流水线：stdin JSON → 插件裁决 → 信封入队 → 退出码。
// 仅实现了 RunPreToolUse 的插件具备前置裁决能力；纯审计型插件（无该能力）恒放行。
func runPreToolUseCLI(agentPlugin core.Plugin, stdin io.Reader, stderr io.Writer,
	envelopeSink func(envelopeBytes []byte), versionText string) int {
	preToolUseRunner, canRun := agentPlugin.(interface {
		RunPreToolUse(stdin io.Reader, stderr io.Writer,
			envelopeSink func(envelopeBytes []byte), agentVersion string) int
	})
	if !canRun {
		return 0
	}
	return preToolUseRunner.RunPreToolUse(stdin, stderr, envelopeSink, versionText)
}

// extractHookPluginTargets 解析 hook 子命令的目标插件与其余配置参数：
//   - 规范形态：紧随子命令的首个位置参数（settings.json 由 install-hook 写入的形态）
//   - 兼容形态：--plugin NAME / --plugin=NAME（可重复时取首个——单进程只做单次裁决）
//
// 其余参数原样交由配置装载；缺省 claude-code。
func extractHookPluginTargets(subArguments []string) ([]string, []string) {
	var targetPluginNames []string
	remainingArguments := make([]string, 0, len(subArguments))
	for argumentIndex := 0; argumentIndex < len(subArguments); argumentIndex++ {
		tokenText := subArguments[argumentIndex]
		switch {
		case tokenText == "--plugin":
			if argumentIndex+1 < len(subArguments) {
				targetPluginNames = appendUniquePluginName(targetPluginNames, subArguments[argumentIndex+1])
				argumentIndex++
			}
		case strings.HasPrefix(tokenText, "--plugin="):
			targetPluginNames = appendUniquePluginName(targetPluginNames,
				strings.TrimPrefix(tokenText, "--plugin="))
		default:
			if argumentIndex == 0 && !strings.HasPrefix(tokenText, "-") {
				targetPluginNames = appendUniquePluginName(targetPluginNames, tokenText)
			} else {
				remainingArguments = append(remainingArguments, tokenText)
			}
		}
	}
	if len(targetPluginNames) == 0 {
		targetPluginNames = []string{schema.AgentTypeClaudeCode}
	}
	return targetPluginNames, remainingArguments
}

// parseHookTargetNames 解析装卸子命令的目标插件名：可重复 --plugin 标记与位置参数混用，
// 词法归一去重保序；装卸命令无其他 flag，未知参数直接报错。无任何目标时返回空切片。
func parseHookTargetNames(flagArguments []string) ([]string, error) {
	var targetNames []string
	for argumentIndex := 0; argumentIndex < len(flagArguments); argumentIndex++ {
		tokenText := flagArguments[argumentIndex]
		switch {
		case tokenText == "--plugin":
			argumentIndex++
			if argumentIndex >= len(flagArguments) {
				return nil, fmt.Errorf("--plugin 缺少值")
			}
			targetNames = appendUniquePluginName(targetNames, flagArguments[argumentIndex])
		case strings.HasPrefix(tokenText, "--plugin="):
			targetNames = appendUniquePluginName(targetNames, strings.TrimPrefix(tokenText, "--plugin="))
		case strings.HasPrefix(tokenText, "-"):
			return nil, fmt.Errorf("未知参数 %s", tokenText)
		default:
			targetNames = appendUniquePluginName(targetNames, tokenText)
		}
	}
	return targetNames, nil
}

// appendUniquePluginName 词法归一（trim+小写）后保序去重追加。
func appendUniquePluginName(targetNames []string, rawName string) []string {
	normalized := strings.ToLower(strings.TrimSpace(rawName))
	for _, existingName := range targetNames {
		if existingName == normalized {
			return targetNames
		}
	}
	return append(targetNames, normalized)
}

// installHookCommand 安装指定插件的前置 Hook 到对应宿主（缺省 claude-code；
// 可重复 --plugin 或位置参数）。不支持 Hook 的插件打印提示并按成功处理（退出码不受影响）。
func installHookCommand(flagArguments []string) int {
	targetNames, parseErr := parseHookTargetNames(flagArguments)
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n用法: a3-agent install-hook [[--plugin] 名称]...\n", parseErr)
		return 1
	}
	if len(targetNames) == 0 {
		targetNames = []string{schema.AgentTypeClaudeCode}
	}
	homeDir, homeErr := core.ResolveHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}
	exitCode := 0
	for _, targetName := range targetNames {
		pluginRegistry, registryErr := buildRegistry([]string{targetName}, homeDir)
		if registryErr != nil {
			fmt.Fprintf(os.Stderr, "%v\n", registryErr)
			exitCode = 1
			continue
		}
		changed, configureErr := pluginRegistry.All()[0].ConfigureHook(homeDir, true)
		if errors.Is(configureErr, core.ErrHookUnsupported) {
			fmt.Printf("ℹ️ %s 不支持前置 Hook（纯审计采集，无需安装）\n", targetName)
			continue
		}
		if configureErr != nil {
			fmt.Fprintf(os.Stderr, "安装 %s 失败: %v\n", targetName, configureErr)
			exitCode = 1
			continue
		}
		if changed {
			fmt.Printf("✅ 已安装 %s 前置 Hook 到宿主配置（原配置已备份）\n", targetName)
		} else {
			fmt.Printf("ℹ️ %s Hook 已存在，无需重复安装\n", targetName)
		}
	}
	return exitCode
}

// uninstallHookCommand 卸载指定插件的前置 Hook；无参时清理全部内置插件的 a3 项。
// 不支持 Hook 的插件本就无可卸载内容，静默跳过。
func uninstallHookCommand(flagArguments []string) int {
	targetNames, parseErr := parseHookTargetNames(flagArguments)
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n用法: a3-agent uninstall-hook [[--plugin] 名称]...\n", parseErr)
		return 1
	}
	homeDir, homeErr := core.ResolveHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}
	if len(targetNames) == 0 {
		targetNames = sortedBuiltinPluginNames()
	}
	exitCode := 0
	for _, targetName := range targetNames {
		pluginRegistry, registryErr := buildRegistry([]string{targetName}, homeDir)
		if registryErr != nil {
			fmt.Fprintf(os.Stderr, "%v\n", registryErr)
			exitCode = 1
			continue
		}
		changed, configureErr := pluginRegistry.All()[0].ConfigureHook(homeDir, false)
		if errors.Is(configureErr, core.ErrHookUnsupported) {
			continue
		}
		if configureErr != nil {
			fmt.Fprintf(os.Stderr, "卸载 %s 失败: %v\n", targetName, configureErr)
			exitCode = 1
			continue
		}
		if changed {
			fmt.Printf("✅ 已移除 %s 前置 Hook\n", targetName)
		} else {
			fmt.Printf("ℹ️ 未发现已安装的 %s 前置 Hook\n", targetName)
		}
	}
	return exitCode
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
