package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/pkg/schema"
)

// writeTestSnapshot 在 <home>/.a3 下落一份规则快照（模拟 run 进程写入）。
func writeTestSnapshot(t *testing.T, homeDirectory string, snapshot schema.RulesSnapshotFile) {
	t.Helper()
	stateDirectory := filepath.Join(homeDirectory, ".a3")
	require.NoError(t, os.MkdirAll(stateDirectory, 0o700))
	snapshotBytes, marshalErr := json.Marshal(snapshot)
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(filepath.Join(stateDirectory, schema.RulesSnapshotFileName), snapshotBytes, 0o600))
}

const builtinTriggerCommand = `{"command":"rm -rf / --no-preserve-root"}`

func TestHookUsesSnapshotCustomRule(t *testing.T) {
	t.Setenv("A3_STATE_DIR", "")
	homeDirectory := t.TempDir()
	writeTestSnapshot(t, homeDirectory, schema.RulesSnapshotFile{
		Version: schema.RulesSnapshotVersion, Revision: "sha256:test",
		Rules: []schema.RuleDefinition{{
			ID: "custom.forbidden", Name: "禁用操作", Target: "command",
			Patterns: []string{"forbidden-ops"}, Severity: "high", Action: "block",
		}},
	})

	claudePlugin, buildErr := NewPlugin(homeDirectory)
	require.NoError(t, buildErr)
	matchedTags := claudePlugin.ruleMatcher.EvaluateHookInput([]byte(`{"command":"run forbidden-ops now"}`))
	require.Len(t, matchedTags, 1)
	assert.Equal(t, "custom.forbidden", matchedTags[0].Code)
}

func TestHookCorruptSnapshotFallsBackToBuiltin(t *testing.T) {
	t.Setenv("A3_STATE_DIR", "")
	homeDirectory := t.TempDir()
	stateDirectory := filepath.Join(homeDirectory, ".a3")
	require.NoError(t, os.MkdirAll(stateDirectory, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stateDirectory, schema.RulesSnapshotFileName),
		[]byte("{broken json"), 0o600))

	claudePlugin, buildErr := NewPlugin(homeDirectory)
	require.NoError(t, buildErr)
	matchedTags := claudePlugin.ruleMatcher.EvaluateHookInput([]byte(builtinTriggerCommand))
	require.NotEmpty(t, matchedTags, "损坏快照应回落内置清单并命中内置规则")
	assert.Equal(t, "cmd.rm_rf_root", matchedTags[0].Code)
}

func TestHookEmptySnapshotMeansServerSideAllowAll(t *testing.T) {
	t.Setenv("A3_STATE_DIR", "")
	homeDirectory := t.TempDir()
	writeTestSnapshot(t, homeDirectory, schema.RulesSnapshotFile{
		Version: schema.RulesSnapshotVersion, Revision: "sha256:empty", Rules: []schema.RuleDefinition{},
	})

	claudePlugin, buildErr := NewPlugin(homeDirectory)
	require.NoError(t, buildErr)
	matchedTags := claudePlugin.ruleMatcher.EvaluateHookInput([]byte(builtinTriggerCommand))
	assert.Empty(t, matchedTags,
		"替换制语义：服务端显式下发空集（全部停用）时终端不得回落内置拦截")
}

func TestHookBrokenSnapshotRuleFallsBackToBuiltin(t *testing.T) {
	t.Setenv("A3_STATE_DIR", "")
	homeDirectory := t.TempDir()
	writeTestSnapshot(t, homeDirectory, schema.RulesSnapshotFile{
		Version: schema.RulesSnapshotVersion, Revision: "sha256:broken-rule",
		Rules: []schema.RuleDefinition{{
			ID: "custom.bad", Name: "坏正则", Target: "command",
			Patterns: []string{"([unclosed"}, Severity: "high", Action: "block",
		}},
	})

	claudePlugin, buildErr := NewPlugin(homeDirectory)
	require.NoError(t, buildErr)
	matchedTags := claudePlugin.ruleMatcher.EvaluateHookInput([]byte(builtinTriggerCommand))
	require.NotEmpty(t, matchedTags, "快照含不可编译条目应整体回落内置")
}
