package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core"
)

// 自检结果标记。
const (
	doctorVersionLabel = "版本"
	doctorConfigLabel  = "配置"
	doctorIdentity     = "设备身份"
	doctorSpool        = "断网缓存"
	doctorHookLabel    = "前置 Hook"
	doctorServiceLabel = "常驻服务"
)

// doctorReport 逐项自检结果：写入 writer 并累计失败/警告计数。
type doctorReport struct {
	writer   io.Writer
	problems int
	warnings int
}

func (report *doctorReport) pass(label string, format string, args ...any) {
	fmt.Fprintf(report.writer, "[通过] %s：%s\n", label, fmt.Sprintf(format, args...))
}

func (report *doctorReport) warn(label string, format string, args ...any) {
	report.warnings++
	fmt.Fprintf(report.writer, "[警告] %s：%s\n", label, fmt.Sprintf(format, args...))
}

func (report *doctorReport) fail(label string, format string, args ...any) {
	report.problems++
	fmt.Fprintf(report.writer, "[失败] %s：%s\n", label, fmt.Sprintf(format, args...))
}

func (report *doctorReport) info(format string, args ...any) {
	fmt.Fprintf(report.writer, "[信息] %s\n", fmt.Sprintf(format, args...))
}

// doctorCommand 自检子命令入口：装配配置后委托 runDoctor。
// 配置装载与校验以「服务端地址是否解析出来」呈现——未登记（server-url 缺失）
// 就是自检要指出的问题之一，因此不在入口中断，由 runDoctor 的失败项表达。
func doctorCommand(flagArguments []string) int {
	homeDir, homeErr := core.ResolveHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 2
	}
	agentConfig := core.Default(homeDir)
	agentConfig.ApplyEnv(os.Getenv)
	return runDoctor(homeDir, agentConfig, os.Stdout, true)
}

// runDoctor 自检核心，可注入 homeDir/config/writer 便于沙箱测试；
// runExternal=false 时跳过一切外部副作用（服务实时状态、网络探测）。
// 全绿（可含警告）返回 0，任一「失败」级问题返回 2。
func runDoctor(homeDir string, agentConfig core.Config, writer io.Writer, runExternal bool) int {
	report := &doctorReport{writer: writer}
	fmt.Fprintf(writer, "== a3-agent 自检（版本 %s | 平台 %s/%s） ==\n", agentVersion, runtime.GOOS, runtime.GOARCH)

	// 1. 版本
	report.pass(doctorVersionLabel, "a3-agent %s", agentVersion)

	// 2. 配置装载：服务端地址（env A3_SERVER_URL 或 register 持久化的 server-url）
	serverURL := strings.TrimSpace(agentConfig.ServerURL)
	parsedServerURL, parseErr := url.Parse(serverURL)
	if serverURL == "" || parseErr != nil ||
		(parsedServerURL.Scheme != "http" && parsedServerURL.Scheme != "https") || parsedServerURL.Host == "" {
		report.fail(doctorConfigLabel, "服务端地址缺失或非法（%q）。未登记请执行:\n    a3-agent register --server http://<服务端地址>:8080", serverURL)
		serverURL = ""
	} else {
		report.pass(doctorConfigLabel, "服务端: %s", serverURL)
	}

	// 3. 设备身份：register 固定写入 ~/.a3，run 按 StateDir 读取——
	//    两者一致时用 StateDir，不一致时以已存在身份的实际位置为准。
	identityDir := agentConfig.StateDir
	if !hasStoredIdentity(identityDir) && hasStoredIdentity(filepath.Join(homeDir, ".a3")) {
		identityDir = filepath.Join(homeDir, ".a3")
	}
	if hasStoredIdentity(identityDir) {
		report.pass(doctorIdentity, "已登记（%s、%s）",
			filepath.Join(identityDir, deviceTokenFileName), filepath.Join(identityDir, deviceIDFileName))
	} else if serverURL != "" {
		report.fail(doctorIdentity, "未登记——无法上报。请执行:\n    a3-agent register --server %s\n（凭据经终端粘贴提交，不进命令行/URL/日志）", serverURL)
	} else {
		report.fail(doctorIdentity, "未登记——无法上报。请按上方「配置」指引先完成 register 登记")
	}

	// 4. 断网缓存可写
	probeFilePath := filepath.Join(agentConfig.SpoolDir, fmt.Sprintf(".doctor-probe-%d", time.Now().UnixNano()))
	if mkdirErr := os.MkdirAll(agentConfig.SpoolDir, 0o700); mkdirErr == nil {
		if writeErr := os.WriteFile(probeFilePath, []byte("a3 doctor write probe\n"), 0o600); writeErr == nil {
			_ = os.Remove(probeFilePath)
			report.pass(doctorSpool, "可写（%s），断网事件可离线留存", agentConfig.SpoolDir)
		} else {
			report.fail(doctorSpool, "写入探针失败: %v（%s）", writeErr, agentConfig.SpoolDir)
		}
	} else {
		report.fail(doctorSpool, "无法创建目录: %v（%s）", mkdirErr, agentConfig.SpoolDir)
	}

	// 5. 采集监听目录：逐启用插件声明的根目录（缺失 = 该 AI 工具未装/未用，不判失败）
	pluginRegistry, registryErr := buildRegistry(agentConfig.Plugins, homeDir)
	if registryErr != nil {
		report.warn("采集监听", "插件装配失败: %v", registryErr)
	} else {
		for _, agentPlugin := range pluginRegistry.All() {
			for specIndex, watchSpec := range agentPlugin.LogWatchSpecs(homeDir) {
				watchLabel := fmt.Sprintf("监听 %s#%d", agentPlugin.Name(), specIndex)
				if _, statErr := os.Stat(watchSpec.RootDirectory); statErr == nil {
					report.pass(watchLabel, "%s", watchSpec.RootDirectory)
				} else {
					report.warn(watchLabel, "目录不存在（%s）——对应 AI 工具未安装/未使用，装好后自动开始采集", watchSpec.RootDirectory)
				}
			}
		}
	}

	// 6. 前置 Hook：~/.claude/settings.json 是否含 a3 标记（hookCommandMarker 字面量）
	if runtime.GOOS == "windows" {
		report.info("Windows 暂无前置 Hook 支持（纯审计采集）")
	} else {
		agentBinPath := filepath.Join(homeDir, agentBinSubPath)
		settingsRaw, readErr := os.ReadFile(filepath.Join(homeDir, ".claude", "settings.json"))
		if readErr == nil && strings.Contains(string(settingsRaw), "hook pretooluse") {
			report.pass(doctorHookLabel, "已装入 ~/.claude/settings.json")
		} else {
			report.warn(doctorHookLabel, "未检测到——装好后才有高危阻断。请执行:\n    %s install-hook", agentBinPath)
		}
	}

	// 7. 常驻服务：文件存在即可（install-service 失败不阻断采集，故缺失仅警告）
	switch runtime.GOOS {
	case "darwin":
		plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", launchdPlistName)
		if fileExists(plistPath) {
			report.pass(doctorServiceLabel, "launchd plist 已安装（%s）", plistPath)
			if runExternal {
				_ = exec.Command("launchctl", "print", "gui/"+uidString()+"/"+launchdLabel).Run()
			}
		} else {
			report.warn(doctorServiceLabel, "未安装——仅前台 run 可用。请执行:\n    %s install-service", filepath.Join(homeDir, agentBinSubPath))
		}
	case "linux":
		unitPath := filepath.Join(homeDir, ".config", "systemd", "user", systemdUnitName)
		if fileExists(unitPath) {
			report.pass(doctorServiceLabel, "systemd user unit 已安装（%s）", unitPath)
			if runExternal {
				_ = exec.Command("systemctl", "--user", "is-active", systemdUnitName).Run()
			}
		} else {
			report.warn(doctorServiceLabel, "未安装——仅前台 run 可用。请执行:\n    %s install-service", filepath.Join(homeDir, agentBinSubPath))
		}
	default:
		report.warn(doctorServiceLabel, "%s 需手动服务化（install-service 当前不支持）", runtime.GOOS)
	}

	// 8. 服务端连通性：3s 超时探测 /healthz（存活 + DB 就绪，与 webDist 无关）；
	//    失败仅警告（离线/自签名/地址错误时采集以缓存兜底）
	if !runExternal {
		report.info("跳过服务端连通性探测（测试/非交互模式）")
	} else if serverURL == "" {
		report.warn("连通性", "服务端地址未配置，跳过探测")
	} else {
		httpClient := &http.Client{Timeout: 3 * time.Second}
		if agentConfig.InsecureTLS {
			httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 显式 A3_INSECURE_SKIP_TLS_VERIFY 场景
			}
		}
		probeResponse, probeErr := httpClient.Get(serverURL + "/healthz")
		if probeErr != nil {
			report.warn("连通性", "无法连通服务端 %s: %v（断网/自签名/地址错误时属正常，断网续传兜底）", serverURL, probeErr)
		} else {
			probeResponse.Body.Close()
			if probeResponse.StatusCode == http.StatusOK {
				report.pass("连通性", "服务端 %s 可达", serverURL)
			} else {
				report.warn("连通性", "服务端 %s 返回 HTTP %d", serverURL, probeResponse.StatusCode)
			}
		}
	}

	switch {
	case report.problems > 0:
		fmt.Fprintf(writer, "\n自检结果：%d 项问题、%d 项警告——存在需处理项（退出码 2）\n", report.problems, report.warnings)
		return 2
	case report.warnings > 0:
		fmt.Fprintf(writer, "\n自检结果：通过，%d 项警告可忽略（退出码 0）\n", report.warnings)
	default:
		fmt.Fprintf(writer, "\n自检结果：全部通过（退出码 0）\n")
	}
	return 0
}

// hasStoredIdentity 判断状态目录下是否已有完整设备身份（device-token + device-id 均非空）。
func hasStoredIdentity(stateDirectory string) bool {
	tokenBytes, tokenErr := os.ReadFile(filepath.Join(stateDirectory, deviceTokenFileName))
	if tokenErr != nil || strings.TrimSpace(string(tokenBytes)) == "" {
		return false
	}
	idBytes, idErr := os.ReadFile(filepath.Join(stateDirectory, deviceIDFileName))
	return idErr == nil && strings.TrimSpace(string(idBytes)) != ""
}