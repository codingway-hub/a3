package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderLaunchdPlist(t *testing.T) {
	plistText := renderLaunchdPlist("/Users/demo/.a3/bin/a3-agent", "/Users/demo/.a3/agent.log", false)

	assert.Contains(t, plistText, "<string>/Users/demo/.a3/bin/a3-agent</string>")
	assert.Contains(t, plistText, "<string>run</string>")
	assert.Contains(t, plistText, "com.a3.agent")
	assert.Contains(t, plistText, "<key>RunAtLoad</key><true/>", "登录时启动")
	assert.Contains(t, plistText, "<key>KeepAlive</key><true/>", "崩溃拉起")
	assert.Contains(t, plistText, "<string>/Users/demo/.a3/agent.log</string>")
	// 服务单元不得写死服务端地址：run 进程自读 server-url
	// （排除 plist DOCTYPE 的 Apple 标准 DTD URL 行）
	for _, textLine := range strings.Split(plistText, "\n") {
		if strings.Contains(textLine, "http://") && !strings.Contains(textLine, "DTDs/PropertyList") {
			t.Fatalf("plist 出现疑似服务端地址的行: %s", textLine)
		}
	}
}

func TestRenderSystemdUnit(t *testing.T) {
	unitText := renderSystemdUnit("/home/demo/.a3/bin/a3-agent", "/home/demo/.a3/agent.log")

	assert.Contains(t, unitText, "ExecStart=/home/demo/.a3/bin/a3-agent run")
	assert.Contains(t, unitText, "Restart=on-failure")
	assert.Contains(t, unitText, "RestartSec=5")
	assert.Contains(t, unitText, "WantedBy=default.target", "user unit 挂 default.target")
	assert.NotContains(t, unitText, "http://", "unit 不应包含服务端地址")
}

func TestEnsureOwnedServiceFile(t *testing.T) {
	serviceDir := t.TempDir()
	plistPath := filepath.Join(serviceDir, "com.a3.agent.plist")
	serviceContent := renderLaunchdPlist("/bin/a3-agent", "/tmp/a3.log", false)

	// 首次写入 + 重复写入幂等
	require.NoError(t, ensureOwnedServiceFile(plistPath, serviceContent, 0644))
	require.NoError(t, ensureOwnedServiceFile(plistPath, serviceContent, 0644))
	rereadBytes, readErr := os.ReadFile(plistPath)
	require.NoError(t, readErr)
	assert.Equal(t, serviceContent, string(rereadBytes))
	assert.Empty(t, tempFilesIn(t, serviceDir), "写入完成后不得残留临时文件")

	// 目录下已有同名非 a3 文件：保护性拒绝
	foreignPath := filepath.Join(serviceDir, "foreign.plist")
	require.NoError(t, os.WriteFile(foreignPath, []byte("user's own file"), 0644))
	foreignErr := ensureOwnedServiceFile(foreignPath, serviceContent, 0644)
	require.Error(t, foreignErr)
	assert.Contains(t, foreignErr.Error(), "拒绝覆盖")
	foreignBytes, _ := os.ReadFile(foreignPath)
	assert.Equal(t, "user's own file", string(foreignBytes), "用户文件内容不得被改动")
}

func TestRemoveServiceFile(t *testing.T) {
	serviceDir := t.TempDir()

	// 未安装：幂等成功由 removeServiceFile 返回码表达（0）
	assert.Equal(t, 0, removeServiceFile(filepath.Join(serviceDir, "missing.plist")))

	// a3 标记文件可删
	ownedPath := filepath.Join(serviceDir, "com.a3.agent.plist")
	require.NoError(t, ensureOwnedServiceFile(ownedPath,
		renderLaunchdPlist("/bin/a3-agent", "/tmp/a3.log", false), 0644))
	assert.Equal(t, 0, removeServiceFile(ownedPath))
	assert.NoFileExists(t, ownedPath)

	// 非 a3 文件保护性拒绝（返回码 1，文件保留）
	foreignPath := filepath.Join(serviceDir, "foreign.plist")
	require.NoError(t, os.WriteFile(foreignPath, []byte("user's own file"), 0644))
	assert.Equal(t, 1, removeServiceFile(foreignPath))
	assert.FileExists(t, foreignPath)
}

func tempFilesIn(t *testing.T, directory string) []string {
	t.Helper()
	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	leftovers := make([]string, 0)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".a3-service-") {
			leftovers = append(leftovers, entry.Name())
		}
	}
	return leftovers
}

func TestRenderLaunchdPlistAppMode(t *testing.T) {
	plistText := renderLaunchdPlist("/Users/demo/.a3/bin/a3-agent", "/Users/demo/.a3/agent.log", true)

	// macOS 15 本地网络模式：经 /usr/bin/open 拉起应用包装，周期性保镖兜底
	assert.Contains(t, plistText, "<string>/usr/bin/open</string>")
	assert.Contains(t, plistText, "<string>-g</string>")
	assert.Contains(t, plistText, "<string>/Users/demo/.a3/A3Agent.app</string>")
	assert.Contains(t, plistText, "<string>--args</string>")
	assert.Contains(t, plistText, "<string>run</string>")
	assert.Contains(t, plistText, "<key>RunAtLoad</key><true/>")
	assert.Contains(t, plistText, "<key>StartInterval</key><integer>120</integer>", "崩溃兜底靠周期重拉")
	assert.NotContains(t, plistText, "<key>KeepAlive</key>", "open 拉起为即返进程，KeepAlive 无从跟踪采集本体")
	for _, textLine := range strings.Split(plistText, "\n") {
		if strings.Contains(textLine, "http://") && !strings.Contains(textLine, "DTDs/PropertyList") {
			t.Fatalf("plist 出现疑似服务端地址的行: %s", textLine)
		}
	}
}

func TestRenderAppInfoPlist(t *testing.T) {
	infoText := renderAppInfoPlist()
	assert.Contains(t, infoText, "<key>CFBundleIdentifier</key><string>com.a3.agent</string>")
	assert.Contains(t, infoText, "<key>CFBundleExecutable</key><string>a3-agent</string>")
	assert.Contains(t, infoText, "<key>CFBundlePackageType</key><string>APPL</string>")
	assert.Contains(t, infoText, "<key>LSBackgroundOnly</key><true/>", "后台运行不占 Dock")
	assert.Contains(t, infoText, "com.a3.agent", "归属标记：卸载时校验")
}

func TestRenderAppLauncherScript(t *testing.T) {
	binPath := "/Users/demo/.a3/bin/a3-agent"
	logPath := "/Users/demo/.a3/agent.log"
	script := renderAppLauncherScript(binPath, logPath)

	assert.Contains(t, script, "#!/bin/sh")
	assert.Contains(t, script, `pgrep -f "`+binPath+` run"`, "已在运行则退出，避免周期重拉起第二实例")
	assert.Contains(t, script, `exec "`+binPath+`" "${@:-run}"`)
	assert.Contains(t, script, `>> "`+logPath+`" 2>&1`, "exec 前自定向日志：open 拉起时 launchd 无法捕获采集器 stdout")
}

func TestInstallLocalNetworkApp(t *testing.T) {
	homeDir := t.TempDir()
	binDir := filepath.Join(homeDir, ".a3", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	binPath := filepath.Join(binDir, "a3-agent")
	require.NoError(t, os.WriteFile(binPath, []byte("fake-agent"), 0o755))
	logPath := filepath.Join(homeDir, agentLogSubPath)

	require.NoError(t, installLocalNetworkApp(homeDir, binPath, logPath))

	bundleDir := filepath.Join(homeDir, ".a3", launchdAppBundleName)
	require.FileExists(t, filepath.Join(bundleDir, "Contents", "Info.plist"))
	launcherPath := filepath.Join(bundleDir, "Contents", "MacOS", "a3-agent")
	require.FileExists(t, launcherPath)
	launcherBytes, readErr := os.ReadFile(launcherPath)
	require.NoError(t, readErr)
	assert.Contains(t, string(launcherBytes), `exec "`+binPath+`"`, "启动器 exec 采集器本体")
	launcherInfo, statErr := os.Stat(launcherPath)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o755), launcherInfo.Mode().Perm(), "启动器需可执行")

	// 重复安装幂等（覆盖写，不残留）
	require.NoError(t, installLocalNetworkApp(homeDir, binPath, logPath))
	bundleEntries, _ := os.ReadDir(bundleDir)
	assert.Len(t, bundleEntries, 1, "仅 Contents 一个子目录")
}

func TestRemoveLocalNetworkApp(t *testing.T) {
	homeDir := t.TempDir()
	bundleDir := filepath.Join(homeDir, ".a3", launchdAppBundleName)

	// 未安装：幂等成功
	assert.Equal(t, 0, removeLocalNetworkApp(homeDir))

	binDir := filepath.Join(homeDir, ".a3", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	binPath := filepath.Join(binDir, "a3-agent")
	require.NoError(t, os.WriteFile(binPath, []byte("fake-agent"), 0o755))
	require.NoError(t, installLocalNetworkApp(homeDir, binPath, filepath.Join(homeDir, ".a3", "agent.log")))

	assert.Equal(t, 0, removeLocalNetworkApp(homeDir))
	assert.NoDirExists(t, bundleDir)

	// 非 a3 应用包：保护性拒绝
	foreignDir := filepath.Join(homeDir, ".a3", "A3Agent.app")
	require.NoError(t, os.MkdirAll(filepath.Join(foreignDir, "Contents"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(foreignDir, "Contents", "Info.plist"), []byte("user's own app"), 0644))
	assert.Equal(t, 1, removeLocalNetworkApp(homeDir))
	assert.DirExists(t, foreignDir, "非 a3 应用包不得被删除")
}

func TestParseDarwinMajor(t *testing.T) {
	for version, want := range map[string]int{
		"24.1.0": 24,
		"24A348": 24,
		"25.0.0": 25,
		"23.6.0": 23, // macOS 14
		"":        0,
		"not-a-number": 0,
	} {
		assert.Equal(t, want, parseDarwinMajor(version), "版本 %q", version)
	}
}
