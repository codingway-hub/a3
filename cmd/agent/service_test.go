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
	plistText := renderLaunchdPlist("/Users/demo/.a3/bin/a3-agent", "/Users/demo/.a3/agent.log")

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
	serviceContent := renderLaunchdPlist("/bin/a3-agent", "/tmp/a3.log")

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
		renderLaunchdPlist("/bin/a3-agent", "/tmp/a3.log"), 0644))
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
