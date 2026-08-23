package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeAgentPath = "/usr/local/bin/a3-agent"

func readSettingsHooks(t *testing.T, settingsPath string) []hookEntry {
	t.Helper()
	rawBytes, readErr := os.ReadFile(settingsPath)
	require.NoError(t, readErr)
	var settingsFile struct {
		Hooks struct {
			PreToolUse []hookEntry `json:"PreToolUse"`
		} `json:"hooks"`
		OtherField string `json:"other_field"`
	}
	require.NoError(t, json.Unmarshal(rawBytes, &settingsFile))
	return settingsFile.Hooks.PreToolUse
}

func TestInstallHookOnEmptyDirectory(t *testing.T) {
	claudeDirectory := filepath.Join(t.TempDir(), ".claude")

	changed, installErr := InstallHook(claudeDirectory, fakeAgentPath)
	require.NoError(t, installErr)
	assert.True(t, changed)

	hookMatcherEntries := readSettingsHooks(t, filepath.Join(claudeDirectory, "settings.json"))
	require.Len(t, hookMatcherEntries, 1)
	assert.Equal(t, "*", hookMatcherEntries[0].Matcher)
	require.Len(t, hookMatcherEntries[0].Hooks, 1)
	assert.Equal(t, "command", hookMatcherEntries[0].Hooks[0].Type)
	assert.Equal(t, fakeAgentPath+" hook pretooluse", hookMatcherEntries[0].Hooks[0].Command)
}

func TestInstallHookMergesAndKeepsExistingConfig(t *testing.T) {
	claudeDirectory := t.TempDir()
	settingsPath := filepath.Join(claudeDirectory, "settings.json")
	existingSettings := `{"other_field":"keep-me","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-other-hook"}]}]}}`
	require.NoError(t, os.WriteFile(settingsPath, []byte(existingSettings), 0o644))

	changed, installErr := InstallHook(claudeDirectory, fakeAgentPath)
	require.NoError(t, installErr)
	assert.True(t, changed)

	rawBytes, _ := os.ReadFile(settingsPath)
	assert.Contains(t, string(rawBytes), "keep-me", "原有其他配置必须保留")
	hookMatcherEntries := readSettingsHooks(t, settingsPath)
	require.Len(t, hookMatcherEntries, 2)
	assert.Equal(t, "Bash", hookMatcherEntries[0].Matcher, "既有 Hook 项在前且不变")
	assert.Equal(t, "my-other-hook", hookMatcherEntries[0].Hooks[0].Command)
	assert.Equal(t, fakeAgentPath+" hook pretooluse", hookMatcherEntries[1].Hooks[0].Command)

	// 备份恰好一份，且内容为安装前原文
	backupPaths, globErr := filepath.Glob(filepath.Join(claudeDirectory, backupGlobPattern))
	require.NoError(t, globErr)
	require.Len(t, backupPaths, 1)
	backupBytes, readErr := os.ReadFile(backupPaths[0])
	require.NoError(t, readErr)
	assert.JSONEq(t, existingSettings, string(backupBytes))
}

func TestInstallHookIdempotentSecondRun(t *testing.T) {
	claudeDirectory := t.TempDir()

	firstChanged, firstErr := InstallHook(claudeDirectory, fakeAgentPath)
	require.NoError(t, firstErr)
	assert.True(t, firstChanged)

	secondChanged, secondErr := InstallHook(claudeDirectory, fakeAgentPath)
	require.NoError(t, secondErr)
	assert.False(t, secondChanged, "重复安装应跳过")

	hookMatcherEntries := readSettingsHooks(t, filepath.Join(claudeDirectory, "settings.json"))
	assert.Len(t, hookMatcherEntries, 1, "不得产生重复 Hook 项")
}

func TestUninstallRemovesOnlyA3Entry(t *testing.T) {
	claudeDirectory := t.TempDir()
	settingsPath := filepath.Join(claudeDirectory, "settings.json")
	existingSettings := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-other-hook"}]}]}}`
	require.NoError(t, os.WriteFile(settingsPath, []byte(existingSettings), 0o644))
	_, installErr := InstallHook(claudeDirectory, fakeAgentPath)
	require.NoError(t, installErr)

	changed, uninstallErr := UninstallHook(claudeDirectory)
	require.NoError(t, uninstallErr)
	assert.True(t, changed)

	rawBytes, _ := os.ReadFile(settingsPath)
	assert.NotContains(t, string(rawBytes), "a3-agent")
	assert.Contains(t, string(rawBytes), "my-other-hook", "他人 Hook 必须保留")

	// 再次卸载：无 a3 项，返回未变更
	secondChanged, secondErr := UninstallHook(claudeDirectory)
	require.NoError(t, secondErr)
	assert.False(t, secondChanged)
}

func TestUninstallWhenNoSettingsIsNoop(t *testing.T) {
	changed, uninstallErr := UninstallHook(filepath.Join(t.TempDir(), ".claude"))
	require.NoError(t, uninstallErr)
	assert.False(t, changed)
}

func TestConfigureHookDelegationRoundTrip(t *testing.T) {
	claudePlugin := newTestPlugin(t)
	homeDirectory := t.TempDir()

	installedChanged, installErr := claudePlugin.ConfigureHook(homeDirectory, true)
	require.NoError(t, installErr)
	assert.True(t, installedChanged)

	settingsPath := filepath.Join(homeDirectory, ".claude", "settings.json")
	hookMatcherEntries := readSettingsHooks(t, settingsPath)
	require.Len(t, hookMatcherEntries, 1)
	// go test 下 os.Executable 是测试二进制而非 a3-agent，只断言固定子命令标记
	assert.True(t, strings.HasSuffix(hookMatcherEntries[0].Hooks[0].Command, " hook pretooluse"))

	removedChanged, removeErr := claudePlugin.ConfigureHook(homeDirectory, false)
	require.NoError(t, removeErr)
	assert.True(t, removedChanged)
}
