package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/pkg/schema"
)

func TestParseRulesRefreshSeconds(t *testing.T) {
	assert.Equal(t, 300*time.Second, parseRulesRefreshSeconds(""), "缺省 300s")
	assert.Equal(t, 300*time.Second, parseRulesRefreshSeconds("abc"), "非法值按缺省")
	assert.Equal(t, 60*time.Second, parseRulesRefreshSeconds("30"), "低于下限钳到 60s")
	assert.Equal(t, 120*time.Second, parseRulesRefreshSeconds("120"))
	assert.Equal(t, time.Duration(0), parseRulesRefreshSeconds("0"), "显式 0 关闭周期")
	assert.Equal(t, time.Duration(0), parseRulesRefreshSeconds("-5"), "负值关闭周期")
}

func TestWriteRulesSnapshotIfChanged(t *testing.T) {
	stateDirectory := t.TempDir()
	snapshotPath := filepath.Join(stateDirectory, schema.RulesSnapshotFileName)
	payloadV1 := schema.DeviceRulesPayload{
		Revision: "sha256:aaa",
		Rules: []schema.RuleDefinition{{
			ID: "custom.x", Name: "X", Target: "command",
			Patterns: []string{"rm -rf"}, Severity: "high", Action: "block",
		}},
	}

	// 首次写盘：文件生成、形状与权限正确
	changed, writeErr := writeRulesSnapshotIfChanged(snapshotPath, payloadV1)
	require.NoError(t, writeErr)
	assert.True(t, changed)
	rawBytes, readErr := os.ReadFile(snapshotPath)
	require.NoError(t, readErr)
	var snapshot schema.RulesSnapshotFile
	require.NoError(t, json.Unmarshal(rawBytes, &snapshot))
	assert.Equal(t, schema.RulesSnapshotVersion, snapshot.Version)
	assert.Equal(t, "sha256:aaa", snapshot.Revision)
	require.Len(t, snapshot.Rules, 1)
	infoStat, statErr := os.Stat(snapshotPath)
	require.NoError(t, statErr)
	assert.True(t, infoStat.Mode().Perm() == 0o600, "快照含规则明文，权限须收紧")

	// revision 未变：跳过
	changed, writeErr = writeRulesSnapshotIfChanged(snapshotPath, payloadV1)
	require.NoError(t, writeErr)
	assert.False(t, changed)

	// revision 变化：覆盖更新
	payloadV1.Revision = "sha256:bbb"
	changed, writeErr = writeRulesSnapshotIfChanged(snapshotPath, payloadV1)
	require.NoError(t, writeErr)
	assert.True(t, changed)
	rereadBytes, _ := os.ReadFile(snapshotPath)
	assert.Contains(t, string(rereadBytes), "sha256:bbb")
}
