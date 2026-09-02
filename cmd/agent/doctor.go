package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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
	doctorSignature    = "发布签名"
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

// skip 跳过不计数：某些检查（如发布签名）对 pre-P2 存量安装无布局数据，
// 跳过是事实陈述而非缺陷，不能推高退出码。
func (report *doctorReport) skip(label string, format string, args ...any) {
	fmt.Fprintf(report.writer, "[跳过] %s：%s\n", label, fmt.Sprintf(format, args...))
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

	// 3. 发布签名自检：固定安装路径字节 vs 配套 .sig vs 安装期持久化的公钥。
	//    三件缺一 → [跳过]（pre-P2 存量安装无签名布局，不影响退出码）；三件俱备则
	//    ed25519.Verify，失败判[失败]——产物被篡改/损坏/下载不完整。固定路径而非
	//    os.Executable：后者随调用形态漂移（会去核查 /tmp 副本）而绕过常驻字节。
	runAgentSignatureCheck(report, homeDir)

	// 可回滚信息：升级链路保留 a3-agent.prev，列出供回退参考（info 不计数）
	prevVersionBin := filepath.Join(filepath.Dir(agentBinPathFor(homeDir)), "a3-agent.prev")
	if fileExists(prevVersionBin) {
		if runExternal {
			if prevVersion := agentVersionText(prevVersionBin); prevVersion != "" {
				report.info("可回滚：上一版本已保留（%s）——a3-agent rollback 可随时回退", prevVersion)
			} else {
				report.info("上一版本已保留——a3-agent rollback 可随时回退")
			}
		} else {
			report.info("上一版本已保留——a3-agent rollback 可随时回退")
		}
	}

	// 4. 设备身份：register 固定写入 ~/.a3，run 按 StateDir 读取——
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

	// 5. 断网缓存可写
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

	// 6. 采集监听目录：逐启用插件声明的根目录（缺失 = 该 AI 工具未装/未用，不判失败）
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

	// 7. 前置 Hook：~/.claude/settings.json 是否含 a3 标记（hookCommandMarker 字面量）
	if runtime.GOOS == "windows" {
		report.info("Windows 暂无前置 Hook 支持（纯审计采集）")
	} else {
		agentBinPath := agentBinPathFor(homeDir)
		settingsRaw, readErr := os.ReadFile(filepath.Join(homeDir, ".claude", "settings.json"))
		if readErr == nil && strings.Contains(string(settingsRaw), "hook pretooluse") {
			report.pass(doctorHookLabel, "已装入 ~/.claude/settings.json")
		} else {
			report.warn(doctorHookLabel, "未检测到——装好后才有高危阻断。请执行:\n    %s install-hook", agentBinPath)
		}
	}

	// 8. 常驻服务：文件存在即可（install-service 失败不阻断采集，故缺失仅警告）
	switch runtime.GOOS {
	case "darwin":
		plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", launchdPlistName)
		if fileExists(plistPath) {
			report.pass(doctorServiceLabel, "launchd plist 已安装（%s）", plistPath)
			if runExternal {
				_ = exec.Command("launchctl", "print", "gui/"+uidString()+"/"+launchdLabel).Run()
			}
		} else {
			report.warn(doctorServiceLabel, "未安装——仅前台 run 可用。请执行:\n    %s install-service", agentBinPathFor(homeDir))
		}
	case "linux":
		unitPath := filepath.Join(homeDir, ".config", "systemd", "user", systemdUnitName)
		if fileExists(unitPath) {
			report.pass(doctorServiceLabel, "systemd user unit 已安装（%s）", unitPath)
			if runExternal {
				_ = exec.Command("systemctl", "--user", "is-active", systemdUnitName).Run()
			}
		} else {
			report.warn(doctorServiceLabel, "未安装——仅前台 run 可用。请执行:\n    %s install-service", agentBinPathFor(homeDir))
		}
	default:
		report.warn(doctorServiceLabel, "%s 需手动服务化（install-service 当前不支持）", runtime.GOOS)
	}

	// 9. 服务端连通性：3s 超时探测 /healthz（存活 + DB 就绪，与 webDist 无关）；
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

// runAgentSignatureCheck 采集器发布签名自检（doctor 的真正常驻强制关卡，全平台可执行）。
// 三件布局（二进制/.sig/公钥）缺一即[跳过]——pre-P2 或未开签名安装无数据可比，陈述事实
// 而非缺陷；三件俱备则 ed25519.Verify，失败判[失败]（篡改/损坏/下载不完整）。
func runAgentSignatureCheck(report *doctorReport, homeDir string) {
	agentPath := agentBinPathFor(homeDir)
	sigPath := agentPath + ".sig"
	pubKeyPath := filepath.Join(homeDir, ".a3", "agent-pubkey.pem")

	var missing []string
	for _, layoutPath := range []string{agentPath, sigPath, pubKeyPath} {
		if !fileExists(layoutPath) {
			missing = append(missing, layoutPath)
		}
	}
	if len(missing) > 0 {
		report.skip(doctorSignature, "签名布局不全（缺 %s），不校验——pre-P2 存量安装或未开启发布签名", strings.Join(missing, "、"))
		return
	}

	pubKey, parseErr := parseAgentSignPublicKey(pubKeyPath)
	if parseErr != nil {
		report.fail(doctorSignature, "发布公钥解析失败: %v（%s）", parseErr, pubKeyPath)
		return
	}
	agentBytes, readErr := os.ReadFile(agentPath)
	if readErr != nil {
		report.fail(doctorSignature, "读取二进制失败: %v（%s）", readErr, agentPath)
		return
	}
	sigBytes, readErr := os.ReadFile(sigPath)
	if readErr != nil {
		report.fail(doctorSignature, "读取签名失败: %v（%s）", readErr, sigPath)
		return
	}
	if !ed25519.Verify(pubKey, agentBytes, sigBytes) {
		report.fail(doctorSignature, "二进制与发布签名不匹配——产物被篡改或损坏（%s）。请重跑 install.sh 或 a3-agent rollback", agentPath)
		return
	}
	digest := sha256.Sum256(pubKey)
	report.pass(doctorSignature, "%s 与发布签名一致（指纹: %s）", agentPath, hex.EncodeToString(digest[:]))
}

// parseAgentSignPublicKey 从安装期写下的 PEM 文件解析 ed25519 发布公钥（与 install.sh
// 内嵌的公钥同源，用于 doctor 以固定路径复核）。
func parseAgentSignPublicKey(pubKeyPath string) (ed25519.PublicKey, error) {
	rawBytes, readErr := os.ReadFile(pubKeyPath)
	if readErr != nil {
		return nil, readErr
	}
	block, _ := pem.Decode(rawBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("未找到标准 PUBLIC KEY PEM 块")
	}
	parsedKey, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
	if parseErr != nil {
		return nil, parseErr
	}
	pubKey, keyOK := parsedKey.(ed25519.PublicKey)
	if !keyOK {
		return nil, fmt.Errorf("非 ed25519 发布密钥: %T", parsedKey)
	}
	return pubKey, nil
}

// agentVersionText 运行安装路径二进制 version 探测（3s 超时），失败返回空串，
// 供回滚 info 展示上一版本号。
func agentVersionText(agentPath string) string {
	probeContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	versionOutput, runErr := exec.CommandContext(probeContext, agentPath, "version").CombinedOutput()
	if runErr != nil {
		return ""
	}
	return strings.TrimSpace(string(versionOutput))
}