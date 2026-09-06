package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/codingway-hub/a3/internal/agent/core"
)

// 常驻服务装配：install-service / uninstall-service / status 子命令。
// 设计约束与 install-hook 一致：幂等、可还原；不可用环境打印手动指引而非失败。
// 服务单元不写死服务端地址——run 进程自行读取 ~/.a3/server-url（register 持久化）。

const (
	launchdLabel          = "com.a3.agent"
	launchdPlistName      = launchdLabel + ".plist"
	launchdAppBundleName  = "A3Agent.app"
	localNetworkStartSecs = 120
	systemdUnitName       = "a3-agent.service"
	agentLogSubPath       = ".a3/agent.log"
	serviceMarkerToken    = launchdLabel // plist/unit 归属标记：覆盖前校验，防误删用户同名文件
)

// agentBinPathFor 采集器安装的固定二进制路径；Windows 下补 .exe（旧版 agentBinSubPath
// 缺后缀导致 schtasks/doctor 指向不存在文件）。
func agentBinPathFor(homeDir string) string {
	binName := "a3-agent"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	return filepath.Join(homeDir, ".a3", "bin", binName)
}

// appBundlePathFor macOS 15 本地网络模式下，负责启动采集器的极简 .app 包装路径。
func appBundlePathFor(homeDir string) string {
	return filepath.Join(homeDir, ".a3", launchdAppBundleName)
}

// needsLocalNetworkApp 当前 macOS 是否需要「.app 包装 + /usr/bin/open 拉起」的常驻服务形态。
// macOS 15（Darwin 24）起，局域网访问按「责任应用」强制授权：无签名二进制被 launchd 直起时
// 授权被系统静默拒绝（connect() 立即报 EHOSTUNREACH / "no route to host"），表现为设备在
// 控制台「注册后在线几分钟又离线」。必须经 LaunchServices 以应用身份运行，才会出现在系统的
// 「本地网络」授权列表并可被放行。Darwin ≥ 24 即启用该形态；旧版 macOS 维持直起 KeepAlive。
func needsLocalNetworkApp() bool {
	return runtime.GOOS == "darwin" && darwinMajorKernel() >= 24
}

// darwinMajorKernel 读取内核 Darwin 主版本号；失败返回 0（非 darwin 也为 0，不启用包装）。
func darwinMajorKernel() int {
	kernelVersion, versionErr := exec.Command("uname", "-r").Output()
	if versionErr != nil {
		return 0
	}
	return parseDarwinMajor(strings.TrimSpace(string(kernelVersion)))
}

// parseDarwinMajor 提取 Darwin 内核主版本（"24.1.0" → 24；"24A348" → 24；非数字 → 0）。
// 取前导数字字段即可兼容点分版本（uname -r）与构建号（build version）两种形态。
func parseDarwinMajor(kernelVersion string) int {
	var digits string
	for _, versionRune := range kernelVersion {
		if versionRune < '0' || versionRune > '9' {
			break
		}
		digits += string(versionRune)
	}
	major, parseErr := strconv.Atoi(digits)
	if parseErr != nil {
		return 0
	}
	return major
}

// installServiceCommand 安装常驻服务：macOS launchd / Linux systemd user unit；
// Windows 打印手动指引。返回退出码。
func installServiceCommand(flagArguments []string) int {
	homeDir, homeErr := resolveServiceHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}
	agentBinPath := agentBinPathFor(homeDir)
	if _, statErr := os.Stat(agentBinPath); statErr != nil {
		fmt.Fprintf(os.Stderr, "未找到采集器二进制 %s：请先完成安装（curl <服务端>/install.sh | sh）\n", agentBinPath)
		return 1
	}
	logPath := filepath.Join(homeDir, agentLogSubPath)

	switch runtime.GOOS {
	case "darwin":
		return installLaunchdService(homeDir, agentBinPath, logPath)
	case "linux":
		return installSystemdService(homeDir, agentBinPath, logPath)
	case "windows":
		fmt.Println("Windows 暂不支持自动服务化，请以管理员执行（计划任务，登录时启动、失败重启）：")
		fmt.Printf("  schtasks /Create /SC ONLOGON /TN \"a3-agent\" /TR \"%s run\" /F\n", agentBinPath)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "不支持的操作系统 %s：请手动运行 \"%s run\"\n", runtime.GOOS, agentBinPath)
		return 1
	}
}

// installLaunchdService 写 ~/Library/LaunchAgents/com.a3.agent.plist 并 bootstrap。
// macOS 15 起自动切「本地网络」模式：先装配 A3Agent.app 包装，再经 /usr/bin/open 拉起，
// 使采集进程以应用身份出现，从而可在系统「本地网络」授权列表中放行（详见 needsLocalNetworkApp）。
func installLaunchdService(homeDir string, agentBinPath string, logPath string) int {
	appMode := needsLocalNetworkApp()
	if appMode {
		if appErr := installLocalNetworkApp(homeDir, agentBinPath, logPath); appErr != nil {
			fmt.Fprintf(os.Stderr, "装配 macOS 本地网络应用包装失败: %v\n", appErr)
			return 1
		}
	}
	plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", launchdPlistName)
	if overwriteErr := ensureOwnedServiceFile(plistPath,
		renderLaunchdPlist(agentBinPath, logPath, appMode), 0644); overwriteErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", overwriteErr)
		return 1
	}
	// 先卸旧实例再加载：bootout 失败（未加载）属正常，忽略
	_ = exec.Command("launchctl", "bootout", "gui/"+uidString(), plistPath).Run()
	if loadErr := exec.Command("launchctl", "bootstrap", "gui/"+uidString(), plistPath).Run(); loadErr != nil {
		// 旧 macOS 无 bootstrap：回退 load
		if legacyErr := exec.Command("launchctl", "load", plistPath).Run(); legacyErr != nil {
			fmt.Fprintf(os.Stderr, "plist 已写入但加载失败（可重启后自动生效）: %v\n", loadErr)
			return 0
		}
	}
	if appMode {
		fmt.Printf("✅ 常驻服务已安装并启动（macOS 15 本地网络模式）：%s\n日志: %s\n", plistPath, logPath)
		fmt.Println("   首次连内网服务端会请求「本地网络」权限：系统设置 → 隐私与安全性 → 本地网络 → 允许 A3Agent")
		fmt.Println("   授权前系统静默拒绝局域网连接（设备在控制台可能显示离线），授权后数秒内自动恢复在线")
		fmt.Println("   升级/回滚后重启采集：pkill -f \"a3-agent run\"（2 分钟内自动重拉），或立即 open -g ~/.a3/A3Agent.app --args run")
	} else {
		fmt.Printf("✅ 常驻服务已安装并启动：%s\n日志: %s\n", plistPath, logPath)
	}
	return 0
}

// installLocalNetworkApp 在 ~/.a3 下装配极简 A3Agent.app 包装，使采集进程的「责任应用」
// 成为可授权的应用包（macOS 15 本地网络权限按责任应用判定）。布局：
//
//	A3Agent.app/Contents/Info.plist           应用标识（com.a3.agent）
//	A3Agent.app/Contents/MacOS/a3-agent       shell 启动器，exec 采集器本体并自定向日志
//
// 启动器用 exec 而不是子进程：责任应用属性随进程 exec 保持为应用包本体，签到仍归于 app；
// 日志经 shell 重定向自写 agent.log（经 open 拉起时 launchd 无法把 stdout 定向到采集器）。
// 重复安装幂等：重写 plist 与启动器（先删旧文件，避免覆盖场景把符号链接目标误写）。
func installLocalNetworkApp(homeDir string, agentBinPath string, logPath string) error {
	bundleDir := appBundlePathFor(homeDir)
	macosDir := filepath.Join(bundleDir, "Contents", "MacOS")
	if mkdirErr := os.MkdirAll(macosDir, 0o755); mkdirErr != nil {
		return mkdirErr
	}
	if writeErr := os.WriteFile(filepath.Join(bundleDir, "Contents", "Info.plist"),
		[]byte(renderAppInfoPlist()), 0o644); writeErr != nil {
		return writeErr
	}
	launcherPath := filepath.Join(macosDir, "a3-agent")
	if removeErr := os.Remove(launcherPath); removeErr != nil && !os.IsNotExist(removeErr) {
		return removeErr
	}
	return os.WriteFile(launcherPath, []byte(renderAppLauncherScript(agentBinPath, logPath)), 0o755)
}

// renderAppInfoPlist 应用包装的 Info.plist：标识 com.a3.agent（与 launchd 服务一致），
// 后台运行、禁多实例。无签名应用包仅供本地网络授权记账用，无需 code signing。
func renderAppInfoPlist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- ` + launchdLabel + `：macOS 15 本地网络权限所用的应用包装（由 a3-agent install-service 管理，勿手改） -->
<dict>
  <key>CFBundleDisplayName</key><string>A3Agent</string>
  <key>CFBundleExecutable</key><string>a3-agent</string>
  <key>CFBundleIdentifier</key><string>` + launchdLabel + `</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>A3Agent</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSBackgroundOnly</key><true/>
</dict>
</plist>
`
}

// renderAppLauncherScript 应用包装的启动器：已有采集进程直接退出（周期重试不会起第二实例），
// 否则 exec 为采集器本体（注：exec 保留应用责任属性，本地网络授权作用于整个链）。
// pgrep -f 指定安装路径避免误伤同类进程名。
func renderAppLauncherScript(agentBinPath string, logPath string) string {
	return `#!/bin/sh
# ` + launchdLabel + `：macOS 15 本地网络应用启动器（由 a3-agent install-service 生成，勿手改）。
if pgrep -f "` + agentBinPath + ` run" >/dev/null 2>&1; then
  exit 0
fi
exec "` + agentBinPath + `" "${@:-run}" >> "` + logPath + `" 2>&1
`
}

// removeLocalNetworkApp 卸载应用包装；缺失幂等成功，非 a3 包保护性拒绝。返回退出码层级。
func removeLocalNetworkApp(homeDir string) int {
	bundleDir := appBundlePathFor(homeDir)
	infoBytes, statErr := os.ReadFile(filepath.Join(bundleDir, "Contents", "Info.plist"))
	switch {
	case statErr == nil:
		if !strings.Contains(string(infoBytes), launchdLabel) {
			fmt.Fprintf(os.Stderr, "拒绝删除非 a3 的应用包: %s\n", bundleDir)
			return 1
		}
		if removeErr := os.RemoveAll(bundleDir); removeErr != nil {
			fmt.Fprintf(os.Stderr, "删除本地网络应用包装失败: %v\n", removeErr)
			return 1
		}
		fmt.Printf("✅ 已移除 macOS 本地网络应用包装: %s\n", bundleDir)
		return 0
	case os.IsNotExist(statErr):
		return 0 // 幂等成功
	default:
		fmt.Fprintf(os.Stderr, "读取失败: %v\n", statErr)
		return 1
	}
}

// installSystemdService 写 ~/.config/systemd/user/a3-agent.service 并 enable --now。
func installSystemdService(homeDir string, agentBinPath string, logPath string) int {
	systemctlCheck := exec.Command("systemctl", "--user", "is-system-running")
	if systemctlCheck.Run() != nil {
		fmt.Fprintln(os.Stderr, "未检测到可用的 systemd 用户会话，已打印手动命令（不算失败）：")
		fmt.Printf("  nohup %s run >> %s 2>&1 &\n", agentBinPath, logPath)
		return 0
	}
	unitPath := filepath.Join(homeDir, ".config", "systemd", "user", systemdUnitName)
	if overwriteErr := ensureOwnedServiceFile(unitPath,
		renderSystemdUnit(agentBinPath, logPath), 0644); overwriteErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", overwriteErr)
		return 1
	}
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	if enableErr := exec.Command("systemctl", "--user", "enable", "--now", systemdUnitName).Run(); enableErr != nil {
		fmt.Fprintf(os.Stderr, "unit 已写入但启用失败: %v\n", enableErr)
		return 1
	}
	fmt.Printf("✅ 常驻服务已安装并启动：%s\n日志: journalctl --user -u %s -f 或 %s\n", unitPath, systemdUnitName, logPath)
	return 0
}

// uninstallServiceCommand 停止并移除服务单元；不存在时报幂等成功。
func uninstallServiceCommand(flagArguments []string) int {
	homeDir, homeErr := resolveServiceHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}

	switch runtime.GOOS {
	case "darwin":
		plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", launchdPlistName)
		_ = exec.Command("launchctl", "bootout", "gui/"+uidString(), plistPath).Run()
		plistCode := removeServiceFile(plistPath)
		if appCode := removeLocalNetworkApp(homeDir); appCode > plistCode {
			return appCode
		}
		return plistCode
	case "linux":
		unitPath := filepath.Join(homeDir, ".config", "systemd", "user", systemdUnitName)
		_ = exec.Command("systemctl", "--user", "disable", "--now", systemdUnitName).Run()
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		return removeServiceFile(unitPath)
	case "windows":
		fmt.Println("Windows 请手动移除计划任务：")
		fmt.Println("  schtasks /Delete /TN \"a3-agent\" /F")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "不支持的操作系统 %s\n", runtime.GOOS)
		return 1
	}
}

// serviceStatusCommand 打印服务安装与运行状态。
func serviceStatusCommand(flagArguments []string) int {
	homeDir, homeErr := resolveServiceHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}

	fmt.Printf("二进制: %s\n", agentBinPathFor(homeDir))
	switch runtime.GOOS {
	case "darwin":
		plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", launchdPlistName)
		fmt.Printf("plist:  %s（存在: %v）\n", plistPath, fileExists(plistPath))
		if needsLocalNetworkApp() {
			fmt.Printf("本地网络: macOS 15 需在 系统设置 → 隐私与安全性 → 本地网络 允许 A3Agent（应用包装: %s）\n", appBundlePathFor(homeDir))
		}
		_ = exec.Command("launchctl", "print", "gui/"+uidString()+"/"+launchdLabel).Run()
	case "linux":
		unitPath := filepath.Join(homeDir, ".config", "systemd", "user", systemdUnitName)
		fmt.Printf("unit:   %s（存在: %v）\n", unitPath, fileExists(unitPath))
		_ = exec.Command("systemctl", "--user", "status", systemdUnitName, "--no-pager").Run()
	default:
		fmt.Printf("常驻服务化在 %s 上需手动配置\n", runtime.GOOS)
	}
	return 0
}

// ensureOwnedServiceFile 原子写入服务单元；目标已存在且不含 a3 标记时保护性拒绝
// （绝不动用户自己的同名文件）。
func ensureOwnedServiceFile(filePath string, content string, fileMode os.FileMode) error {
	if existingBytes, statErr := os.ReadFile(filePath); statErr == nil {
		if !strings.Contains(string(existingBytes), serviceMarkerToken) {
			return fmt.Errorf("拒绝覆盖非 a3 的既有文件: %s", filePath)
		}
	}
	if mkdirErr := os.MkdirAll(filepath.Dir(filePath), 0755); mkdirErr != nil {
		return mkdirErr
	}
	tempFile, createErr := os.CreateTemp(filepath.Dir(filePath), ".a3-service-*.tmp")
	if createErr != nil {
		return createErr
	}
	tempPath := tempFile.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if _, writeErr := tempFile.WriteString(content); writeErr != nil {
		_ = tempFile.Close()
		return writeErr
	}
	if closeErr := tempFile.Close(); closeErr != nil {
		return closeErr
	}
	if chmodErr := os.Chmod(tempPath, fileMode); chmodErr != nil {
		return chmodErr
	}
	return os.Rename(tempPath, filePath)
}

// removeServiceFile 删除服务单元；存在且非 a3 标记时保护性拒绝，不存在时幂等成功。
func removeServiceFile(filePath string) int {
	existingBytes, statErr := os.ReadFile(filePath)
	switch {
	case statErr == nil:
		if !strings.Contains(string(existingBytes), serviceMarkerToken) {
			fmt.Fprintf(os.Stderr, "拒绝删除非 a3 的文件: %s\n", filePath)
			return 1
		}
		if removeErr := os.Remove(filePath); removeErr != nil {
			fmt.Fprintf(os.Stderr, "删除失败: %v\n", removeErr)
			return 1
		}
		fmt.Printf("✅ 已移除常驻服务: %s\n", filePath)
		return 0
	case os.IsNotExist(statErr):
		fmt.Println("服务未安装（幂等成功）")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "读取失败: %v\n", statErr)
		return 1
	}
}

// renderLaunchdPlist 渲染 macOS 常驻服务 plist。
// appMode=true（macOS 15 本地网络）：经 /usr/bin/open 拉起 .app 包装以获得「责任应用」
// 授权；开机自启靠 RunAtLoad，崩溃兜底靠 StartInterval 周期重试（open 对已在运行的
// app 直接返回，启动器内 pgrep 再兜一层，不会起第二实例）。
// appMode=false（macOS < 15）：KeepAlive 直起二进制。
// 两种形态都不写服务端地址：run 进程自读 ~/.a3/server-url。
func renderLaunchdPlist(agentBinPath string, logPath string, appMode bool) string {
	if appMode {
		appPath := filepath.Join(filepath.Dir(filepath.Dir(agentBinPath)), launchdAppBundleName)
		return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- ` + serviceMarkerToken + `：a3 采集器常驻服务（由 a3-agent install-service 管理，勿手改；macOS 15 本地网络模式） -->
<dict>
  <key>Label</key><string>` + launchdLabel + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/open</string>
    <string>-g</string>
    <string>` + appPath + `</string>
    <string>--args</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>` + strconv.Itoa(localNetworkStartSecs) + `</integer>
  <key>StandardOutPath</key><string>` + logPath + `</string>
  <key>StandardErrorPath</key><string>` + logPath + `</string>
</dict>
</plist>
`
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- ` + serviceMarkerToken + `：a3 采集器常驻服务（由 a3-agent install-service 管理，勿手改） -->
<dict>
  <key>Label</key><string>` + launchdLabel + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + agentBinPath + `</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>` + logPath + `</string>
  <key>StandardErrorPath</key><string>` + logPath + `</string>
</dict>
</plist>
`
}

func renderSystemdUnit(agentBinPath string, logPath string) string {
	return `# ` + serviceMarkerToken + `：a3 采集器常驻服务（由 a3-agent install-service 管理，勿手改）
[Unit]
Description=a3 agent (AI 行为审计采集器)
After=network-online.target

[Service]
ExecStart=` + agentBinPath + ` run
Restart=on-failure
RestartSec=5
StandardOutput=append:` + logPath + `
StandardError=append:` + logPath + `

[Install]
WantedBy=default.target
`
}

func resolveServiceHomeDir() (string, error) {
	homeDir, homeErr := core.ResolveHomeDir()
	if homeErr != nil || strings.TrimSpace(homeDir) == "" {
		return "", fmt.Errorf("无法定位用户主目录，无法安装常驻服务")
	}
	return homeDir, nil
}

// uidString 当前用户 uid 文本（launchctl gui domain 需要）。
func uidString() string {
	if currentUser, userErr := user.Current(); userErr == nil {
		return currentUser.Uid
	}
	return fmt.Sprintf("%d", os.Getuid())
}

func fileExists(filePath string) bool {
	_, statErr := os.Stat(filePath)
	return statErr == nil
}
