package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/codingway-hub/a3/internal/agent/core"
)

// 常驻服务装配：install-service / uninstall-service / status 子命令。
// 设计约束与 install-hook 一致：幂等、可还原；不可用环境打印手动指引而非失败。
// 服务单元不写死服务端地址——run 进程自行读取 ~/.a3/server-url（register 持久化）。

const (
	launchdLabel       = "com.a3.agent"
	launchdPlistName   = launchdLabel + ".plist"
	systemdUnitName    = "a3-agent.service"
	agentBinSubPath    = ".a3/bin/a3-agent"
	agentLogSubPath    = ".a3/agent.log"
	serviceMarkerToken = launchdLabel // plist/unit 归属标记：覆盖前校验，防误删用户同名文件
)

// installServiceCommand 安装常驻服务：macOS launchd / Linux systemd user unit；
// Windows 打印手动指引。返回退出码。
func installServiceCommand(flagArguments []string) int {
	homeDir, homeErr := resolveServiceHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}
	agentBinPath := filepath.Join(homeDir, agentBinSubPath)
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
func installLaunchdService(homeDir string, agentBinPath string, logPath string) int {
	plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", launchdPlistName)
	if overwriteErr := ensureOwnedServiceFile(plistPath,
		renderLaunchdPlist(agentBinPath, logPath), 0644); overwriteErr != nil {
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
	fmt.Printf("✅ 常驻服务已安装并启动：%s\n日志: %s\n", plistPath, logPath)
	return 0
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
		return removeServiceFile(plistPath)
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

	fmt.Printf("二进制: %s\n", filepath.Join(homeDir, agentBinSubPath))
	switch runtime.GOOS {
	case "darwin":
		plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", launchdPlistName)
		fmt.Printf("plist:  %s（存在: %v）\n", plistPath, fileExists(plistPath))
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

func renderLaunchdPlist(agentBinPath string, logPath string) string {
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
