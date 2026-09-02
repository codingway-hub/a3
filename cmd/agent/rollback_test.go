package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rollbackFixture 在沙箱 HOME 下布置安装布局（~/.a3/bin），返回 bin 目录与各路径。
func rollbackFixture(t *testing.T, currentBytes []byte, prevBytes []byte) (binDir, agentPath, prevPath string) {
	t.Helper()
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	binDir = filepath.Join(homeDir, ".a3", "bin")
	agentPath = filepath.Join(binDir, "a3-agent")
	prevPath = filepath.Join(binDir, "a3-agent.prev")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	require.NoError(t, os.WriteFile(agentPath, currentBytes, 0o755))
	require.NoError(t, os.WriteFile(prevPath, prevBytes, 0o755))
	return binDir, agentPath, prevPath
}

// rollbackLeftovers 回滚后不得残留 stage 临时文件。
func rollbackLeftovers(t *testing.T, binDir string) []string {
	t.Helper()
	entries, readErr := os.ReadDir(binDir)
	require.NoError(t, readErr)
	var leftovers []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".a3-agent.rollback.") {
			leftovers = append(leftovers, entry.Name())
		}
	}
	return leftovers
}

func TestRollbackSwapsVersionsAndSigs(t *testing.T) {
	binDir, agentPath, prevPath := rollbackFixture(t, []byte("current-bytes-v1"), []byte("prev-bytes-v0"))
	require.NoError(t, os.WriteFile(agentPath+".sig", []byte("SIG-CURRENT"), 0o600))
	require.NoError(t, os.WriteFile(prevPath+".sig", []byte("SIG-PREV"), 0o600))

	exitCode := rollbackCommand(nil)
	assert.Equal(t, 0, exitCode)

	// 字节交换：当前变 v0、上一版保留 v1
	afterBytes, readErr := os.ReadFile(agentPath)
	require.NoError(t, readErr)
	assert.Equal(t, []byte("prev-bytes-v0"), afterBytes, "a3-agent 应变回上一版本字节")
	prevAfterBytes, readErr := os.ReadFile(prevPath)
	require.NoError(t, readErr)
	assert.Equal(t, []byte("current-bytes-v1"), prevAfterBytes, "原当前版本应收进 .prev")

	// 签名配对同构交换：当前签名变旧、旧签名退为 prev
	sigAfter, readErr := os.ReadFile(agentPath + ".sig")
	require.NoError(t, readErr)
	assert.Equal(t, "SIG-PREV", string(sigAfter))
	prevSigAfter, readErr := os.ReadFile(prevPath + ".sig")
	require.NoError(t, readErr)
	assert.Equal(t, "SIG-CURRENT", string(prevSigAfter))

	assert.Empty(t, rollbackLeftovers(t, binDir), "回滚不得残留 stage 文件")
}

func TestRollbackPreSigMissingCurrentUntracked(t *testing.T) {
	// pre-P2 情景：当前版本有签名、.prev 无配对签名（旧版安装于签名机制之前）
	binDir, agentPath, prevPath := rollbackFixture(t, []byte("current-v1"), []byte("legacy-prev"))
	require.NoError(t, os.WriteFile(agentPath+".sig", []byte("SIG-V1"), 0o600))

	exitCode := rollbackCommand(nil)
	assert.Equal(t, 0, exitCode)

	// 旧版本回正后无配对签名：当前 .sig 收起退进 .prev（保留回滚前版本仍可再滚回）
	assert.NoFileExists(t, agentPath+".sig", "旧版无签名机制，回滚后不应残留当前签名")
	prevSig, readErr := os.ReadFile(prevPath + ".sig")
	require.NoError(t, readErr)
	assert.Equal(t, "SIG-V1", string(prevSig))
	assert.Empty(t, rollbackLeftovers(t, binDir))
}

func TestRollbackNoPrevFails(t *testing.T) {
	binDir, agentPath, _ := rollbackFixture(t, []byte("only-current"), []byte{})
	_ = os.Remove(filepath.Join(binDir, "a3-agent.prev"))

	exitCode := rollbackCommand(nil)
	assert.Equal(t, 1, exitCode, "无上一版本应失败并给出指引")
	currentBytes, _ := os.ReadFile(agentPath)
	assert.Equal(t, []byte("only-current"), currentBytes, "失败时当前版本不得受影响")
}

func TestRollbackRenameFailureKeepsCurrent(t *testing.T) {
	// prev 用目录占位：os.Stat 能通过（存在），但 rename(目录 → 文件) 必然失败（ENOTDIR，
	// 与运行权限无关）——验证 a3-agent 在 swap 任一环节失败时原封不动。
	binDir, agentPath, prevPath := rollbackFixture(t, []byte("current-v1"), []byte("prev-v0"))
	require.NoError(t, os.Remove(prevPath))
	require.NoError(t, os.Mkdir(prevPath, 0o700))

	exitCode := rollbackCommand(nil)
	assert.Equal(t, 1, exitCode)
	currentBytes, _ := os.ReadFile(agentPath)
	assert.Equal(t, []byte("current-v1"), currentBytes, "swap 失败时当前版本必须原封不动")
	assert.Empty(t, rollbackLeftovers(t, binDir), "失败路径不得残留 stage 文件（defer 清理）")
}