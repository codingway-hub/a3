package main

// 前置拦截可选能力端到端验证：install-hook / uninstall-hook / hook 子命令在
// 具备拦截能力（claude-code）与纯审计（codex）两种插件下的行为差异。
// 关键契约：
//   - 纯审计插件不被要求实现 Hook 能力——装配层类型断言探测，绝不再返回哨兵错误；
//   - install-hook codex→友好提示且不动宿主配置，退出码 0；
//   - uninstall-hook codex→无内容可卸载，退出码 0；
//   - hook pretooluse codex→fail-open 放行退出码 0；
//   - install/uninstall claude-code→真实安装/卸载 ~/.claude/settings.json。

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolatedHome 把进程主目录重定向到临时目录（os.UserHomeDir 追随 $HOME）。
func isolatedHome(t *testing.T) string {
	homeDir := newTestHome(t)
	t.Setenv("HOME", homeDir)
	return homeDir
}

func TestInstallHookCodexRefusesLeavesSettingsUntouched(t *testing.T) {
	homeDir := isolatedHome(t)

	exitCode := installHookCommand([]string{"codex"})
	assert.Zero(t, exitCode, "纯审计插件安装 Hook 应成功返回（友好提示而非报错）")

	_, statErr := os.Stat(filepath.Join(homeDir, ".claude", "settings.json"))
	assert.True(t, os.IsNotExist(statErr), "codex 不应写入任何宿主配置")
}

func TestUninstallHookCodexNoop(t *testing.T) {
	isolatedHome(t)

	assert.Zero(t, uninstallHookCommand([]string{"codex"}),
		"纯审计插件无可卸载内容，应静默成功")
}

func TestHookCommandCodexFailsOpen(t *testing.T) {
	homeDir := isolatedHome(t)

	// hook 入口对无拦截能力的插件必须 fail-open：退出码 0，绝不阻断宿主工作流。
	assert.Zero(t, hookCommand([]string{"codex"}))

	// 且不产生任何上报产物（codex 未拦截自然无风险事件）。
	stateDir := filepath.Join(homeDir, ".a3", "state")
	if _, statErr := os.Stat(stateDir); statErr == nil {
		entries, listErr := os.ReadDir(stateDir)
		require.NoError(t, listErr)
		assert.Empty(t, entries, "codex fail-open 不应生成 hook 上报产物")
	}
}

func TestInstallAndUninstallClaudeHookRoundTrip(t *testing.T) {
	homeDir := isolatedHome(t)

	// 安装：写入 ~/.claude/settings.json 且含 a3 标记
	assert.Zero(t, installHookCommand([]string{"claude-code"}))
	settingsPath := filepath.Join(homeDir, ".claude", "settings.json")
	settingsRaw, readErr := os.ReadFile(settingsPath)
	require.NoError(t, readErr, "claude install-hook 应写入 settings.json")
	assert.Contains(t, string(settingsRaw), "hook pretooluse",
		"settings.json 应含 a3 的 PreToolUse 勾子命令")

	// 幂等：重复安装不报错
	assert.Zero(t, installHookCommand([]string{"claude-code"}))

	// 卸载：移除 a3 条目、恢复干净配置
	assert.Zero(t, uninstallHookCommand([]string{"claude-code"}))
	settingsRaw, readErr = os.ReadFile(settingsPath)
	require.NoError(t, readErr)
	assert.NotContains(t, string(settingsRaw), "hook pretooluse",
		"卸载后 settings.json 不应再含 a3 Hook 项")
}
