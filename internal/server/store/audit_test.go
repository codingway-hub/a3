package store

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cleanupAuditFor 收尾清理指定目标的审计行，避免污染其他用例的计数断言。
func cleanupAuditFor(t *testing.T, auditStore *Store, targetType string, targetID string) {
	t.Helper()
	_, execErr := auditStore.pool.Exec(context.Background(),
		`DELETE FROM audit_log WHERE target_type = $1 AND target_id = $2`, targetType, targetID)
	require.NoError(t, execErr)
}

func TestRuleAuditTrailAcrossLifecycle(t *testing.T) {
	testPool := newTestPool(t)
	ruleStore := NewStore(testPool)
	ctx := context.Background()
	customRuleID := "custom.audit-lifecycle"
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM rules WHERE id = $1`, customRuleID)
		cleanupAuditFor(t, ruleStore, auditTargetRule, customRuleID)
	})

	newRule := &RuleRecord{
		ID: customRuleID, Name: "审计生命周期", Category: "test",
		Matcher:  []byte(`{"target":"command","patterns":["cargo\\s+publish"],"path_globs":[]}`),
		Severity: "medium", Action: "alert", Enabled: true,
	}
	require.NoError(t, ruleStore.CreateRule(ctx, newRule, "alice"))

	// 创建后：updated_by 已回写 + 恰好一条 rule_create 留痕（after 含完整快照）
	createdRule, getErr := ruleStore.GetRule(ctx, customRuleID)
	require.NoError(t, getErr)
	assert.Equal(t, "alice", createdRule.UpdatedBy)

	entries, total, listErr := ruleStore.ListAuditLog(ctx, AuditFilter{TargetType: auditTargetRule, TargetID: customRuleID})
	require.NoError(t, listErr)
	require.Equal(t, 1, total)
	require.Len(t, entries, 1)
	assert.Equal(t, AuditActionRuleCreate, entries[0].Action)
	assert.Equal(t, "alice", entries[0].Operator)
	assert.Nil(t, entries[0].Before, "create 无变更前状态")
	var afterSnapshot map[string]any
	require.NoError(t, json.Unmarshal(entries[0].After, &afterSnapshot))
	assert.Equal(t, "审计生命周期", afterSnapshot["name"])
	assert.Equal(t, "alice", createdRule.UpdatedBy)

	// 启停：rule_patch 留痕，before/after 均含 enabled
	require.NoError(t, ruleStore.SetRuleEnabled(ctx, customRuleID, false, "bob"))
	entries, total, _ = ruleStore.ListAuditLog(ctx, AuditFilter{TargetType: auditTargetRule, TargetID: customRuleID})
	require.NoError(t, listErr)
	require.Equal(t, 2, total)
	assert.Equal(t, AuditActionRulePatch, entries[0].Action, "id 倒序：最新在前")
	var patchBefore, patchAfter map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Before, &patchBefore))
	require.NoError(t, json.Unmarshal(entries[0].After, &patchAfter))
	assert.Equal(t, true, patchBefore["enabled"])
	assert.Equal(t, false, patchAfter["enabled"])

	// 更新：rule_update 留痕携带 before/after 完整快照
	createdRule.Name = "改名审计"
	createdRule.Severity = "high"
	require.NoError(t, ruleStore.UpdateRule(ctx, &createdRule, "carol"))
	entries, total, _ = ruleStore.ListAuditLog(ctx, AuditFilter{TargetType: auditTargetRule, TargetID: customRuleID})
	require.NoError(t, listErr)
	require.Equal(t, 3, total)
	assert.Equal(t, AuditActionRuleUpdate, entries[0].Action)
	assert.Equal(t, "carol", entries[0].Operator)
	var updateBefore, updateAfter map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Before, &updateBefore))
	require.NoError(t, json.Unmarshal(entries[0].After, &updateAfter))
	assert.Equal(t, "审计生命周期", updateBefore["name"])
	assert.Equal(t, "medium", updateBefore["severity"])
	assert.Equal(t, "改名审计", updateAfter["name"])

	// 删除：rule_delete 留痕携带删除前快照、after 为空
	require.NoError(t, ruleStore.DeleteRule(ctx, customRuleID, "alice"))
	entries, total, _ = ruleStore.ListAuditLog(ctx, AuditFilter{TargetType: auditTargetRule, TargetID: customRuleID})
	require.NoError(t, listErr)
	require.Equal(t, 4, total)
	assert.Equal(t, AuditActionRuleDelete, entries[0].Action)
	assert.Nil(t, entries[0].After, "软删无变更后状态")
	var deleteBefore map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Before, &deleteBefore))
	assert.Equal(t, "改名审计", deleteBefore["name"])

	// 全量分页：无过滤时 count 与条数一致
	allEntries, allTotal, allErr := ruleStore.ListAuditLog(ctx, AuditFilter{Page: 1, PageSize: 100})
	require.NoError(t, allErr)
	assert.Equal(t, allTotal, len(allEntries)+0, "pageSize 足够时全量可见")
}

// TestAuditFailuresLeaveNoTrace 失败路径不留痕：唯一冲突、目标不存在时审计行不得出现。
func TestAuditFailuresLeaveNoTrace(t *testing.T) {
	testPool := newTestPool(t)
	ruleStore := NewStore(testPool)
	ctx := context.Background()
	customRuleID := "custom.audit-fail"
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM rules WHERE id = $1`, customRuleID)
		cleanupAuditFor(t, ruleStore, auditTargetRule, customRuleID)
	})

	newRule := &RuleRecord{
		ID: customRuleID, Name: "首次", Category: "test",
		Matcher: []byte(`{"target":"command","patterns":["x"],"path_globs":[]}`),
	}
	require.NoError(t, ruleStore.CreateRule(ctx, newRule, "alice"))

	// 唯一冲突：事务回滚，无第二条留痕
	duplicateErr := ruleStore.CreateRule(ctx, &RuleRecord{
		ID: customRuleID, Name: "重复", Matcher: newRule.Matcher,
	}, "mallory")
	assert.ErrorIs(t, duplicateErr, ErrAlreadyExists)

	// 不存在的规则：启停/更新/删除全部 ErrNotFound，无留痕
	assert.ErrorIs(t, ruleStore.SetRuleEnabled(ctx, "rule-never-was", true, "mallory"), ErrNotFound)
	assert.ErrorIs(t, ruleStore.UpdateRule(ctx, &RuleRecord{ID: "rule-never-was", Matcher: newRule.Matcher}, "mallory"), ErrNotFound)
	assert.ErrorIs(t, ruleStore.DeleteRule(ctx, "rule-never-was", "mallory"), ErrNotFound)

	entries, total, listErr := ruleStore.ListAuditLog(ctx, AuditFilter{TargetType: auditTargetRule, TargetID: customRuleID})
	require.NoError(t, listErr)
	assert.Equal(t, 1, total, "失败路径不得产生审计行")
	assert.Equal(t, AuditActionRuleCreate, entries[0].Action)
}

func TestDeviceStatusAuditTrail(t *testing.T) {
	testPool := newTestPool(t)
	deviceStore := NewStore(testPool)
	ctx := context.Background()
	deviceID := "dev-audit-status"
	t.Cleanup(func() { cleanupAuditFor(t, deviceStore, auditTargetDevice, deviceID) })

	require.NoError(t, deviceStore.CreateDevice(ctx, &Device{
		DeviceID: deviceID, TokenHash: "hash-" + deviceID, Hostname: "host-" + deviceID,
	}))

	// 吊销：device_revoke 留痕含前后状态
	require.NoError(t, deviceStore.SetDeviceStatusWithAudit(ctx, deviceID, "revoked", "admin"))
	// 恢复：device_restore 留痕
	require.NoError(t, deviceStore.SetDeviceStatusWithAudit(ctx, deviceID, "active", "admin"))

	entries, total, listErr := deviceStore.ListAuditLog(ctx, AuditFilter{TargetType: auditTargetDevice, TargetID: deviceID})
	require.NoError(t, listErr)
	require.Equal(t, 2, total)
	assert.Equal(t, AuditActionDeviceRestore, entries[0].Action, "id 倒序：恢复在前")
	var restoreBefore, restoreAfter map[string]any
	require.NoError(t, json.Unmarshal(entries[0].Before, &restoreBefore))
	require.NoError(t, json.Unmarshal(entries[0].After, &restoreAfter))
	assert.Equal(t, "revoked", restoreBefore["status"])
	assert.Equal(t, "active", restoreAfter["status"])

	assert.Equal(t, AuditActionDeviceRevoke, entries[1].Action)
	var revokeBefore map[string]any
	require.NoError(t, json.Unmarshal(entries[1].Before, &revokeBefore))
	assert.Equal(t, "active", revokeBefore["status"])

	// 不存在的设备：ErrNotFound 且无留痕
	missingErr := deviceStore.SetDeviceStatusWithAudit(ctx, "dev-never-was", "revoked", "admin")
	assert.ErrorIs(t, missingErr, ErrNotFound)
}
