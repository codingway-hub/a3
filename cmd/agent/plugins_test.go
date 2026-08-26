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
