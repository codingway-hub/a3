package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/pkg/schema"
)

// fakePlugin 测试用最小插件实现，验证 Plugin 接口契约可被满足。
type fakePlugin struct {
	pluginName string
}

func (fake *fakePlugin) Name() string { return fake.pluginName }

func (fake *fakePlugin) LogWatchSpecs(homeDir string) []LogWatchSpec {
	return []LogWatchSpec{{RootDirectory: homeDir + "/.fake", MatchGlob: "*.log"}}
}

func (fake *fakePlugin) ParseLine(sourcePath string, line []byte) ([]schema.Event, error) {
	return nil, nil
}

func (fake *fakePlugin) EvaluateHook(hookRequest HookRequest) (HookDecision, error) {
	return HookDecision{}, nil
}

func (fake *fakePlugin) ConfigureHook(homeDir string, enable bool) (bool, error) {
	return false, nil
}

// 编译期断言：*fakePlugin 必须完整实现 Plugin。
var _ Plugin = (*fakePlugin)(nil)

func TestRegistryRegisterAndAllSorted(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&fakePlugin{pluginName: "zeta-agent"})
	registry.Register(&fakePlugin{pluginName: "alpha-agent"})
	registry.Register(&fakePlugin{pluginName: "claude-code"})

	allPlugins := registry.All()
	require.Len(t, allPlugins, 3)
	assert.Equal(t, []string{"alpha-agent", "claude-code", "zeta-agent"},
		[]string{allPlugins[0].Name(), allPlugins[1].Name(), allPlugins[2].Name()},
		"All 应按名称稳定排序")

	foundPlugin, found := registry.Get("claude-code")
	require.True(t, found)
	assert.Equal(t, "claude-code", foundPlugin.Name())

	_, missing := registry.Get("no-such")
	assert.False(t, missing)
}

func TestRegistryRejectsDuplicateNilAndEmptyNames(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&fakePlugin{pluginName: "claude-code"})

	assert.PanicsWithValue(t,
		`插件注册失败: 名称 "claude-code" 重复注册`,
		func() { registry.Register(&fakePlugin{pluginName: "claude-code"}) })

	assert.Panics(t, func() { registry.Register(nil) })
	assert.Panics(t, func() { registry.Register(&fakePlugin{pluginName: ""}) })
}

// HookRequest 的 JSON 形状必须与 ClaudeCode PreToolUse stdin 协议对齐。
func TestHookRequestJSONShape(t *testing.T) {
	var hookRequest HookRequest
	parseErr := json.Unmarshal([]byte(
		`{"session_id":"sess-1","tool_name":"Bash","tool_input":{"command":"ls"}}`), &hookRequest)
	require.NoError(t, parseErr)
	assert.Equal(t, "sess-1", hookRequest.SessionID)
	assert.Equal(t, "Bash", hookRequest.ToolName)
	assert.JSONEq(t, `{"command":"ls"}`, string(hookRequest.ToolInput))
}
