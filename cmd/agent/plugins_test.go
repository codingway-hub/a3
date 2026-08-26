package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/agent/core"
)

// newTestHome 构造隔离的临时主目录（避免测试读写真实 ~/.claude 等）。
func newTestHome(t *testing.T) string {
	return t.TempDir()
}

func TestBuildRegistryAllExpandsBuiltin(t *testing.T) {
	testRegistry, buildErr := buildRegistry([]string{core.PluginAll}, newTestHome(t))
	require.NoError(t, buildErr)
	assert.Equal(t, []string{"claude-code", "codex"}, enabledPluginNames(testRegistry),
		"all 应展开为全部内置插件（当前内置清单）")
}

func TestBuildRegistryExplicitSelection(t *testing.T) {
	testRegistry, buildErr := buildRegistry([]string{"claude-code"}, newTestHome(t))
	require.NoError(t, buildErr)
	assert.Equal(t, []string{"claude-code"}, enabledPluginNames(testRegistry))
}

func TestBuildRegistryUnknownNameFails(t *testing.T) {
	_, buildErr := buildRegistry([]string{"no-such-plugin"}, newTestHome(t))
	require.Error(t, buildErr)
	assert.Contains(t, buildErr.Error(), "未知插件")
}

func TestMigrateLegacyOffsetsFile(t *testing.T) {
	stateDirectory := t.TempDir()
	logger := core.NewLogger(core.Config{LogLevel: "error"})
	targetStateFile := filepath.Join(stateDirectory, "offsets-claude-code-00.json")

	// 无旧文件：不动
	migrateLegacyOffsetsFile(logger, stateDirectory, targetStateFile, "claude-code", 0)
	_, statErr := os.Stat(targetStateFile)
	assert.True(t, os.IsNotExist(statErr), "无旧文件时不应凭空创建目标文件")

	// 有旧文件 + claude-code spec 0：应改名迁移
	require.NoError(t, os.WriteFile(filepath.Join(stateDirectory, legacyOffsetsFileName),
		[]byte(`{}`), 0o600))
	migrateLegacyOffsetsFile(logger, stateDirectory, targetStateFile, "claude-code", 0)
	_, statErr = os.Stat(targetStateFile)
	assert.NoError(t, statErr, "旧文件应被改名到新命名")
	_, statErr = os.Stat(filepath.Join(stateDirectory, legacyOffsetsFileName))
	assert.True(t, os.IsNotExist(statErr), "旧命名文件迁移后应消失")

	// 目标已存在：不动旧文件
	require.NoError(t, os.WriteFile(filepath.Join(stateDirectory, legacyOffsetsFileName),
		[]byte(`{}`), 0o600))
	migrateLegacyOffsetsFile(logger, stateDirectory, targetStateFile, "claude-code", 0)
}

func TestExtractHookPluginTargets(t *testing.T) {
	// 规范形态：紧随子命令的首个位置参数
	targetNames, remainingArgs := extractHookPluginTargets([]string{"codex"})
	assert.Equal(t, []string{"codex"}, targetNames)
	assert.Empty(t, remainingArgs)

	// 缺省：claude-code（兼容一期无尾参条目）
	targetNames, remainingArgs = extractHookPluginTargets(nil)
	assert.Equal(t, []string{"claude-code"}, targetNames)

	// --plugin 标记（=与分离两种写法），其余 flag 原样透传
	targetNames, remainingArgs = extractHookPluginTargets(
		[]string{"--plugin=codex", "--log-level", "debug"})
	assert.Equal(t, []string{"codex"}, targetNames)
	assert.Equal(t, []string{"--log-level", "debug"}, remainingArgs)

	// 分离式 --plugin 值被完整消费，不会误当位置参数
	targetNames, remainingArgs = extractHookPluginTargets([]string{"--plugin", "codex"})
	assert.Equal(t, []string{"codex"}, targetNames)
	assert.Empty(t, remainingArgs)

	// 首参为 flag 时不再识别后续位置参数（避免把其他 flag 的值误判为插件名）
	targetNames, remainingArgs = extractHookPluginTargets(
		[]string{"--state-dir", "/tmp/x", "claude-code"})
	assert.Equal(t, []string{"claude-code"}, targetNames, "缺省插件")
	assert.Equal(t, []string{"--state-dir", "/tmp/x", "claude-code"}, remainingArgs)
}

func TestParseHookTargetNames(t *testing.T) {
	targetNames, parseErr := parseHookTargetNames([]string{"codex", "--plugin", "Claude-Code", "--plugin=bash-x"})
	require.NoError(t, parseErr)
	assert.Equal(t, []string{"codex", "claude-code", "bash-x"}, targetNames,
		"词法归一去重保序")

	// 无目标 → 空切片
	targetNames, parseErr = parseHookTargetNames(nil)
	require.NoError(t, parseErr)
	assert.Empty(t, targetNames)

	// 未知 flag 与缺值报错
	_, parseErr = parseHookTargetNames([]string{"--bogus"})
	assert.Error(t, parseErr)
	_, parseErr = parseHookTargetNames([]string{"--plugin"})
	assert.Error(t, parseErr)
}
