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

	changed, installErr := InstallHook(claudeDirectory, fakeAgentPath, "claude-code")
	require.NoError(t, installErr)
	assert.True(t, changed)

	hookMatcherEntries := readSettingsHooks(t, filepath.Join(claudeDirectory, "settings.json"))
	require.Len(t, hookMatcherEntries, 1)
	assert.Equal(t, "*", hookMatcherEntries[0].Matcher)
	require.Len(t, hookMatcherEntries[0].Hooks, 1)
	assert.Equal(t, "command", hookMatcherEntries[0].Hooks[0].Type)
	assert.Equal(t, fakeAgentPath+" hook pretooluse claude-code", hookMatcherEntries[0].Hooks[0].Command)
}

func TestInstallHookMergesAndKeepsExistingConfig(t *testing.T) {
	claudeDirectory := t.TempDir()
	settingsPath := filepath.Join(claudeDirectory, "settings.json")
	existingSettings := `{"other_field":"keep-me","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-other-hook"}]}]}}`
	require.NoError(t, os.WriteFile(settingsPath, []byte(existingSettings), 0o644))

	changed, installErr := InstallHook(claudeDirectory, fakeAgentPath, "claude-code")
	require.NoError(t, installErr)
	assert.True(t, changed)

	rawBytes, _ := os.ReadFile(settingsPath)
	assert.Contains(t, string(rawBytes), "keep-me", "原有其他配置必须保留")
	hookMatcherEntries := readSettingsHooks(t, settingsPath)
	require.Len(t, hookMatcherEntries, 2)
	assert.Equal(t, "Bash", hookMatcherEntries[0].Matcher, "既有 Hook 项在前且不变")
	assert.Equal(t, "my-other-hook", hookMatcherEntries[0].Hooks[0].Command)
	assert.Equal(t, fakeAgentPath+" hook pretooluse claude-code", hookMatcherEntries[1].Hooks[0].Command)

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

	firstChanged, firstErr := InstallHook(claudeDirectory, fakeAgentPath, "claude-code")
	require.NoError(t, firstErr)
	assert.True(t, firstChanged)

	secondChanged, secondErr := InstallHook(claudeDirectory, fakeAgentPath, "claude-code")
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
	_, installErr := InstallHook(claudeDirectory, fakeAgentPath, "claude-code")
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
	// go test 下 os.Executable 是测试二进制而非 a3-agent，只断言固定子命令标记与插件尾参
	assert.True(t, strings.HasSuffix(hookMatcherEntries[0].Hooks[0].Command, " hook pretooluse claude-code"))

	removedChanged, removeErr := claudePlugin.ConfigureHook(homeDirectory, false)
	require.NoError(t, removeErr)
	assert.True(t, removedChanged)
}

func TestInstallHookUpgradesLegacyEntry(t *testing.T) {
	claudeDirectory := t.TempDir()
	settingsPath := filepath.Join(claudeDirectory, "settings.json")
	// 一期写入的旧形态（无插件尾参）
	require.NoError(t, os.WriteFile(settingsPath, []byte(`{"hooks":{"PreToolUse":[
		{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/a3-agent hook pretooluse"}]}
	]}}`), 0o644))

	changed, installErr := InstallHook(claudeDirectory, fakeAgentPath, "claude-code")
	require.NoError(t, installErr)
	assert.True(t, changed)

	hookMatcherEntries := readSettingsHooks(t, settingsPath)
	require.Len(t, hookMatcherEntries, 1, "旧形态条目应被替换而非追加")
	assert.Equal(t, fakeAgentPath+" hook pretooluse claude-code",
		hookMatcherEntries[0].Hooks[0].Command)
}

func TestUninstallPluginHookScopedRemoval(t *testing.T) {
	claudeDirectory := t.TempDir()
	settingsPath := filepath.Join(claudeDirectory, "settings.json")
	existingSettings := `{"hooks":{"PreToolUse":[
		{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/a3-agent hook pretooluse claude-code"}]},
		{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/a3-agent hook pretooluse codex"}]},
		{"matcher":"Bash","hooks":[{"type":"command","command":"my-other-hook"}]}
	]}}`
	require.NoError(t, os.WriteFile(settingsPath, []byte(existingSettings), 0o644))

	changed, uninstallErr := UninstallPluginHook(claudeDirectory, "codex")
	require.NoError(t, uninstallErr)
	assert.True(t, changed)

	hookMatcherEntries := readSettingsHooks(t, settingsPath)
	require.Len(t, hookMatcherEntries, 2)
	assert.Equal(t, fakeAgentPath+" hook pretooluse claude-code",
		hookMatcherEntries[0].Hooks[0].Command)
	assert.Equal(t, "my-other-hook", hookMatcherEntries[1].Hooks[0].Command,
		"他人 Hook 必须保留")

	// 全量清理：剩余 a3 项全部移除
	allChanged, allErr := UninstallHook(claudeDirectory)
	require.NoError(t, allErr)
	assert.True(t, allChanged)
	hookMatcherEntries = readSettingsHooks(t, settingsPath)
	assert.Len(t, hookMatcherEntries, 1)
	assert.Equal(t, "my-other-hook", hookMatcherEntries[0].Hooks[0].Command)
}

func TestParseA3HookCommandForms(t *testing.T) {
	testCases := []struct {
		commandText       string
		currentBinaryPath string
		expectPlugin      string
		expectRecognized  bool
	}{
		{"/usr/local/bin/a3-agent hook pretooluse", "", "claude-code", true},
		{"/usr/local/bin/a3-agent hook pretooluse", "/usr/local/bin/a3-agent", "claude-code", true},
		{"/usr/local/bin/a3-agent hook pretooluse claude-code", "", "claude-code", true},
		{"/usr/local/bin/a3-agent hook pretooluse codex", "", "codex", true},
		{`"/Applications/My A3/a3-agent" hook pretooluse claude-code`, "", "claude-code", true},
		// 手工追加参数的容错形态：仍识别为 a3 项，插件归属取缺省（保证升级清理不留孤儿条目）
		{"/usr/local/bin/a3-agent hook pretooluse claude-code extra", "", "claude-code", true},
		{"my-other-hook --do-things", "", "", false},
	}
	for _, testCase := range testCases {
		pluginName, recognized := parseA3HookCommand(testCase.commandText, testCase.currentBinaryPath)
		assert.Equal(t, testCase.expectRecognized, recognized, "命令: %s", testCase.commandText)
		if testCase.expectRecognized {
			assert.Equal(t, testCase.expectPlugin, pluginName, "命令: %s", testCase.commandText)
		}
	}
}
