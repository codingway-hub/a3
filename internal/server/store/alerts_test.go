package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustCreateAlert 造一条告警并回填 id。
func mustCreateAlert(t *testing.T, alertStore *Store, ruleID string, severity string) string {
	t.Helper()
	newAlert := &Alert{
		DeviceID: "dev-alert-1", SessionKey: "sess-alert", EventID: "evt-" + ruleID,
		RuleID: ruleID, RuleName: "规则-" + ruleID,
		Severity: severity, Action: "alert",
		Snippet: "片段", Summary: "摘要",
	}
	require.NoError(t, alertStore.CreateAlert(context.Background(), newAlert))
	assert.Equal(t, "open", newAlert.Status, "新告警初始状态应为 open")
	return newAlert.ID
}

func TestAlertLifecycle(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts")
	alertStore := NewStore(testPool)
	ctx := context.Background()

	firstID := mustCreateAlert(t, alertStore, "dlp.jwt", "high")
	secondID := mustCreateAlert(t, alertStore, "cmd.rm_rf_root", "high")
	thirdID := mustCreateAlert(t, alertStore, "file.dotenv_access", "medium")

	// 确认第一条
	require.NoError(t, alertStore.AcknowledgeAlert(ctx, firstID))
	fetchedList, _, listErr := alertStore.ListAlerts(ctx, AlertFilter{Status: "open"})
	require.NoError(t, listErr)
	assert.Len(t, fetchedList, 2, "确认后 open 只剩两条")

	// 重复确认幂等成功
	require.NoError(t, alertStore.AcknowledgeAlert(ctx, firstID))
	// 不存在的告警返回 ErrNotFound
	randomUUID := "00000000-0000-0000-0000-000000000001"
	missErr := alertStore.AcknowledgeAlert(ctx, randomUUID)
	assert.ErrorIs(t, missErr, ErrNotFound)

	openCount, countErr := alertStore.CountOpenAlerts(ctx)
	require.NoError(t, countErr)
	assert.Equal(t, 2, openCount)

	// severity 过滤
	mediumList, mediumTotal, mediumErr := alertStore.ListAlerts(ctx, AlertFilter{Severity: "medium"})
	require.NoError(t, mediumErr)
	assert.Equal(t, 1, mediumTotal)
	assert.Equal(t, thirdID, mediumList[0].ID)

	// 分页
	pageOne, allTotal, pageErr := alertStore.ListAlerts(ctx, AlertFilter{Page: 1, PageSize: 2})
	require.NoError(t, pageErr)
	assert.Equal(t, 3, allTotal)
	assert.Len(t, pageOne, 2)

	// created_at 倒序：最新创建的排最前
	allList, _, orderErr := alertStore.ListAlerts(ctx, AlertFilter{})
	require.NoError(t, orderErr)
	assert.Equal(t, thirdID, allList[0].ID)
	assert.NotEmpty(t, secondID)

	// 确认时间戳已写入
	acknowledgedList, _, ackErr := alertStore.ListAlerts(ctx, AlertFilter{Status: "acknowledged"})
	require.NoError(t, ackErr)
	require.Len(t, acknowledgedList, 1)
	require.NotNil(t, acknowledgedList[0].AcknowledgedAt)
	assert.WithinDuration(t, time.Now(), *acknowledgedList[0].AcknowledgedAt, 10*time.Second)
}
