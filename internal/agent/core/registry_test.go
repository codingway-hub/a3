package core

import (
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/pkg/schema"
)

// fakePlugin 测试用最小插件实现，验证 Plugin 基干接口契约可被满足。
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

// 编译期断言：*fakePlugin 必须完整实现 Plugin 基干。
var _ Plugin = (*fakePlugin)(nil)

// fakeHookPlugin 额外实现前置拦截能力（与 codex 对立的最小形态），
// 验证类型断言探测可选能力的工作方式。
type fakeHookPlugin struct {
	fakePlugin
	evaluated    int
	reportedDoom bool
}

func (fake *fakeHookPlugin) EvaluateHook(hookRequest HookRequest) (HookDecision, error) {
	fake.evaluated++
	decision := HookDecision{Block: fake.reportedDoom}
	if fake.reportedDoom {
		decision.Reason = "test doom"
	}
	return decision, nil
}

func (fake *fakeHookPlugin) ConfigureHook(homeDir string, enable bool) (bool, error) {
	return false, nil
}

func (fake *fakeHookPlugin) RunPreToolUse(stdin io.Reader, stderr io.Writer,
	envelopeSink func([]byte), agentVersion string) int {
	return 0
}

var _ PreToolUsePlugin = (*fakeHookPlugin)(nil)

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

// 可选能力以类型断言探测：纯审计插件不实现 PreToolUsePlugin，前置拦截插件实现。
// 装配层（cmd/agent）据此决定安装/裁决/放行，而非依赖哨兵错误。
func TestOptionalHookCapabilityDiscernedByTypeAssertion(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&fakePlugin{pluginName: "codex"})
	registry.Register(&fakeHookPlugin{fakePlugin: fakePlugin{pluginName: "claude-code"}})

	codexPlugin, _ := registry.Get("codex")
	_, codexCanIntercept := codexPlugin.(PreToolUsePlugin)
	assert.False(t, codexCanIntercept, "纯审计插件不应具备前置拦截能力")

	claudePlugin, found := registry.Get("claude-code")
	require.True(t, found)
	hookPlugin, claudeCanIntercept := claudePlugin.(PreToolUsePlugin)
	assert.True(t, claudeCanIntercept, "claude 插件应具备前置拦截能力")
	decision, decideErr := hookPlugin.EvaluateHook(HookRequest{SessionID: "sess", ToolUseID: "call-1"})
	require.NoError(t, decideErr)
	assert.False(t, decision.Block, "无命中规则应放行")
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
