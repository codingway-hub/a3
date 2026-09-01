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

// persistServerURL 把服务端地址写入 StateDir（0600），供 run/常驻服务在无
// A3_SERVER_URL 环境变量时回退读取；失败仅返回错误由调用方决定是否告警，不阻断注册。
func persistServerURL(stateDirectory string, serverURL string) error {
	return os.WriteFile(filepath.Join(stateDirectory, "server-url"), []byte(serverURL), 0600)
}

// resolveDeviceIdentity 依次尝试：CLI/env Token → 本地状态文件；注册入口唯一化为显式 register。
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
	return "", "", fmt.Errorf(
		"缺少设备 Token：请先执行 a3-agent register --server %s 完成注册",
		agentConfig.ServerURL)
}

// registerCommand 显式注册子命令（薄壳）：解析 flag 后委托 registerDeviceCore。
// 凭据读取、身份复用等安全语义见 registerDeviceCore。
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
	return registerDeviceCore(stateDir, *serverURL, *insecureTLS,
		os.Stdin, os.Stdout, os.Stderr)
}

// registerDeviceCore 注册核心流程：
//  1. 设备身份已存在（device-token + device-id）→ 复用原身份，跳过注册；
//  2. 否则从 stdin 读取管理员一次性安装凭据，携指纹注册→领取新 Token 落盘。
//
// 凭据仅经 stdin 交互/管道读取，绝不进入命令行参数/URL/脚本内容/日志；
// 明文不落盘，读取后仅存于内存请求体。返回进程退出码。
func registerDeviceCore(stateDir string, serverURL string, insecureTLS bool,
	stdin io.Reader, stdout io.Writer, stderr io.Writer) int {

	// 重装/重复执行：设备身份已存在即复用，无需再注册。
	// 服务端对重复安装复用同一设备身份、不轮换 Token；本机保留原 Token 继续上报即可。
	if readStoredDeviceToken(stateDir) != "" && readStoredDeviceID(stateDir) != "" {
		fmt.Fprintf(stdout, "已在册：设备身份已存在（%s），无需重新注册。如需换发 Token，请由管理员吊销后再装。\n",
			storedFilePath(stateDir, deviceTokenFileName))
		return 0
	}

	// 管理员一次性安装凭据：仅经 stdin 交互读取（交互终端提示或安装脚本管道喂入），
	// 明文不落盘、不进参数、不打日志——读取完成即仅存于内存请求体。
	installCode, promptErr := promptInstallCode(stdin, stderr)
	if promptErr != nil {
		fmt.Fprintf(stderr, "注册失败: %v\n", promptErr)
		return 1
	}

	uploaderClient, uploaderErr := transport.NewUploader(serverURL, "", agentVersion, insecureTLS, nil)
	if uploaderErr != nil {
		fmt.Fprintf(stderr, "%v\n", uploaderErr)
		return 1
	}
	ctxWithTimeout, cancelTimeout := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelTimeout()

	fingerprint := buildMachineFingerprint()
	// 重复注册必须携带既有 Token 作为凭证证明（同指纹只认凭证、不认指纹换发）；
	// 完整身份存在时上方已跳过注册，此处仅覆盖残缺身份（有 Token 无 device-id 等）场景。
	credentialToken := readStoredDeviceToken(stateDir)
	registrationResult, registerErr := uploaderClient.RegisterDevice(ctxWithTimeout, transport.DeviceInfo{
		Hostname: shortHostname(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		MachineFingerprint: fingerprint,
		InstallCode:        installCode,
	}, credentialToken)
	if registerErr != nil {
		if credentialToken == "" {
			var rejectedErr *transport.NonRetryableError
			if errors.As(registerErr, &rejectedErr) && rejectedErr.StatusCode == http.StatusConflict {
				fmt.Fprintf(stderr,
					"注册失败：本机指纹已登记在其他设备身份。\n"+
						"本机未找到可用的既有 Token（%s 不存在或已清空）。\n"+
						"请恢复该文件后重试，或联系管理员在控制台吊销该设备后重新注册。\n",
					storedFilePath(stateDir, deviceTokenFileName))
				return 1
			}
		}
		fmt.Fprintf(stderr, "注册失败: %v\n", registerErr)
		return 1
	}
	if storeErr := storeDeviceIdentity(stateDir, registrationResult.Token, registrationResult.DeviceID); storeErr != nil {
		fmt.Fprintf(stderr, "保存身份失败: %v\n", storeErr)
		return 1
	}
	if persistErr := persistServerURL(stateDir, serverURL); persistErr != nil {
		fmt.Fprintf(stderr, "警告：服务端地址写盘失败（run/常驻服务时需设 A3_SERVER_URL）: %v\n", persistErr)
	}
	fmt.Fprintf(stdout, "✅ 注册成功\ndevice_id = %s\ntoken     = %s（已保存至 %s）\n",
		registrationResult.DeviceID, registrationResult.Token,
		filepath.Join(stateDir, deviceTokenFileName))
	return 0
}

// promptInstallCode 从 stdin 读取管理员下发的一次性安装凭据：
//   - 交互终端（stdin 为 TTY）时在 stderr 给出提示后整行读取并回车提交；
//   - 非交互（安装脚本管道喂入）时整行读取，供脚本把凭据经 stdin 传给本命令。
//
// 凭据绝不进入命令行参数、URL、脚本内容或日志；读取后仅存于内存用于请求体。
// 返回错误时调用方终止注册（不可静默跳过——缺凭据注册必然被服务端拒绝）。
func promptInstallCode(stdin io.Reader, stderr io.Writer) (string, error) {
	fmt.Fprintln(stderr, "请输入管理员下发的一次性安装凭据，回车提交")
	fmt.Fprintln(stderr, "（凭据仅经 stdin 提交，绝不写入命令行、URL 或日志）")
	rawBytes, readErr := readLineNoEcho(stdin)
	if readErr != nil {
		return "", fmt.Errorf("读取安装凭据失败: %w", readErr)
	}
	code := strings.TrimSpace(string(rawBytes))
	if code == "" {
		return "", errors.New("安装凭据不能为空")
	}
	fmt.Fprintln(stderr)
	return code, nil
}

// readLineNoEcho 读取一行的原始字节直至换行（EOF 且已有内容时也返回该行）。
func readLineNoEcho(stdin io.Reader) ([]byte, error) {
	var lineBuilder strings.Builder
	oneByte := make([]byte, 1)
	for {
		_, readErr := stdin.Read(oneByte)
		if readErr != nil {
			if readErr == io.EOF && lineBuilder.Len() > 0 {
				return []byte(lineBuilder.String()), nil
			}
			return nil, readErr
		}
		if oneByte[0] == '\n' {
			return []byte(lineBuilder.String()), nil
		}
		lineBuilder.WriteByte(oneByte[0])
	}
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
