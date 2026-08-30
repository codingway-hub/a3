package store

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/agent/plugins/claude"
)

func TestBuiltinRulesSeededAndToggle(t *testing.T) {
	testPool := newTestPool(t)
	ruleStore := NewStore(testPool)
	ctx := context.Background()

	allRules, allErr := ruleStore.ListRules(ctx)
	require.NoError(t, allErr)
	assert.Len(t, allRules, 14, "迁移种子应恰好内置 14 条规则")

	enabledRules, enabledErr := ruleStore.ListEnabledRules(ctx)
	require.NoError(t, enabledErr)
	assert.Len(t, enabledRules, 14)
	for _, rule := range enabledRules {
		assert.True(t, rule.Builtin, "种子规则均为 builtin")
		require.NotEmpty(t, rule.Matcher, "matcher jsonb 不应为空")
	}

	// 停用 → 启用列表减少 → 恢复
	toggleTarget := "dlp.jwt"
	require.NoError(t, ruleStore.SetRuleEnabled(ctx, toggleTarget, false, "store-tester"))
	afterDisable, disableErr := ruleStore.ListEnabledRules(ctx)
	require.NoError(t, disableErr)
	assert.Len(t, afterDisable, 13)

	t.Cleanup(func() {
		_ = ruleStore.SetRuleEnabled(context.Background(), toggleTarget, true, "store-tester") // 恢复现场，避免污染其他用例
	})

	require.NoError(t, ruleStore.SetRuleEnabled(ctx, toggleTarget, true, "store-tester"))
	afterEnable, enableErr := ruleStore.ListEnabledRules(ctx)
	require.NoError(t, enableErr)
	assert.Len(t, afterEnable, 14)

	toggleErr := ruleStore.SetRuleEnabled(ctx, "rule-not-exists", false, "store-tester")
	assert.ErrorIs(t, toggleErr, ErrNotFound)
}

// TestMigrateRestoresRuleSeeds 在整库重置（含迁移簿记）后重放迁移，
// 验证种子 INSERT 幂等：全新库恢复 14 条，重复执行不产生重复行。
func TestMigrateRestoresRuleSeeds(t *testing.T) {
	ctx := context.Background()

	// 用独立原始连接重置 schema 并重放迁移，避免复用池内连接的预编译语句缓存
	rawConnection, connectErr := pgx.Connect(ctx, testDatabaseURLForTest(t))
	require.NoError(t, connectErr)
	defer func() { _ = rawConnection.Close(ctx) }()

	_, dropSchemaErr := rawConnection.Exec(ctx,
		`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`)
	require.NoError(t, dropSchemaErr)
	require.NoError(t, Migrate(ctx, rawConnection))
	require.NoError(t, Migrate(ctx, rawConnection), "重复迁移不得报错或产生重复种子")

	freshPool, poolErr := newFreshTestPool(t)
	require.NoError(t, poolErr)
	t.Cleanup(freshPool.Close)

	ruleStore := NewStore(freshPool)
	restoredRules, restoreErr := ruleStore.ListRules(ctx)
	require.NoError(t, restoreErr)
	assert.Len(t, restoredRules, 14, "整库重置后重放迁移应恰好恢复 14 条规则种子")
}

// TestBuiltinRulesMatchTerminalSource 双端规则同源守护测试（回归审查项 I-2）：
// 迁移落库的内置规则必须与终端 BuiltinRules 逐字段一致——
// id/name/category/severity/action 与 matcher 内的 target/patterns/path_globs。
// 终端清单是权威源；本测试锁死两端，防止任一侧单方面改动造成判定分叉。
func TestBuiltinRulesMatchTerminalSource(t *testing.T) {
	testPool := newTestPool(t)
	ruleStore := NewStore(testPool)

	seededRules, listErr := ruleStore.ListRules(context.Background())
	require.NoError(t, listErr)
	require.Len(t, seededRules, len(claude.BuiltinRules), "种子条数应与终端清单一致")

	seededRuleMap := make(map[string]RuleRecord, len(seededRules))
	for _, seededRule := range seededRules {
		seededRuleMap[seededRule.ID] = seededRule
	}

	for _, terminalRule := range claude.BuiltinRules {
		seededRule, ruleExists := seededRuleMap[terminalRule.ID]
		require.True(t, ruleExists, "规则 %s 未出现在迁移种子中", terminalRule.ID)

		var seededMatcher struct {
			Target    string   `json:"target"`
			Patterns  []string `json:"patterns"`
			PathGlobs []string `json:"path_globs"`
		}
		require.NoError(t, json.Unmarshal(seededRule.Matcher, &seededMatcher),
			"规则 %s matcher 不是合法 JSON", terminalRule.ID)

		assert.Equal(t, terminalRule.Name, seededRule.Name, "规则 %s 名称漂移", terminalRule.ID)
		assert.Equal(t, terminalRule.Category, seededRule.Category, "规则 %s 类别漂移", terminalRule.ID)
		assert.Equal(t, terminalRule.Severity, seededRule.Severity, "规则 %s 等级漂移", terminalRule.ID)
		assert.Equal(t, terminalRule.Action, seededRule.Action, "规则 %s 动作漂移", terminalRule.ID)
		assert.Equal(t, terminalRule.Target, seededMatcher.Target, "规则 %s target 漂移", terminalRule.ID)
		assert.Equal(t, terminalRule.Patterns, seededMatcher.Patterns,
			"规则 %s 正则与终端不一致", terminalRule.ID)
		assert.Equal(t, terminalRule.PathGlobs, seededMatcher.PathGlobs,
			"规则 %s path glob 与终端不一致", terminalRule.ID)
	}
}

// TestCustomRuleCRUDAndSoftDelete 自定义规则全生命周期：
// 创建（含唯一键冲突）→ 更新 → builtin 守护 → 软删后对全部读路径不可见。
func TestCustomRuleCRUDAndSoftDelete(t *testing.T) {
	testPool := newTestPool(t)
	ruleStore := NewStore(testPool)
	ctx := context.Background()
	customRuleID := "custom.test-rule"
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM rules WHERE id = $1`, customRuleID)
	})

	baselineRules, baselineErr := ruleStore.ListRules(ctx)
	require.NoError(t, baselineErr)

	newRule := &RuleRecord{
		ID: customRuleID, Name: "测试规则", Category: "test",
		Matcher:  []byte(`{"target":"command","patterns":["rm\\s+-rf"],"path_globs":[]}`),
		Severity: "high", Action: "alert", Enabled: true,
	}
	require.NoError(t, ruleStore.CreateRule(ctx, newRule, "store-tester"))
	assert.False(t, newRule.CreatedAt.IsZero(), "RETURNING 应回填创建时间")

	duplicateErr := ruleStore.CreateRule(ctx, &RuleRecord{
		ID: customRuleID, Name: "重复", Matcher: []byte(`{"target":"command","patterns":["x"]}`),
	}, "store-tester")
	assert.ErrorIs(t, duplicateErr, ErrAlreadyExists)

	gotRule, getErr := ruleStore.GetRule(ctx, customRuleID)
	require.NoError(t, getErr)
	gotRule.Name = "改名后"
	require.NoError(t, ruleStore.UpdateRule(ctx, &gotRule, "store-tester"))
	rereadRule, rereadErr := ruleStore.GetRule(ctx, customRuleID)
	require.NoError(t, rereadErr)
	assert.Equal(t, "改名后", rereadRule.Name)

	// builtin 行内容不可改/不可删
	updateBuiltinErr := ruleStore.UpdateRule(ctx, &RuleRecord{ID: "dlp.jwt", Name: "篡改"}, "store-tester")
	assert.ErrorIs(t, updateBuiltinErr, ErrNotFound)
	deleteBuiltinErr := ruleStore.DeleteRule(ctx, "dlp.jwt", "store-tester")
	assert.ErrorIs(t, deleteBuiltinErr, ErrNotFound)

	require.NoError(t, ruleStore.DeleteRule(ctx, customRuleID, "store-tester"))
	_, getDeletedErr := ruleStore.GetRule(ctx, customRuleID)
	assert.ErrorIs(t, getDeletedErr, ErrNotFound)
	afterDeleteRules, listErr := ruleStore.ListRules(ctx)
	require.NoError(t, listErr)
	assert.Len(t, afterDeleteRules, len(baselineRules), "软删行不应出现在列表中")
	reDeleteErr := ruleStore.DeleteRule(ctx, customRuleID, "store-tester")
	assert.ErrorIs(t, reDeleteErr, ErrNotFound)
	setEnabledOnDeletedErr := ruleStore.SetRuleEnabled(ctx, customRuleID, true, "store-tester")
	assert.ErrorIs(t, setEnabledOnDeletedErr, ErrNotFound)
}
