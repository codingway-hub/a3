package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListUnnotifiedAlertsFiltering(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts")
	alertStore := NewStore(testPool)
	ctx := context.Background()

	highFirst := mustCreateAlert(t, alertStore, "dlp.jwt", "high")
	_ = mustCreateAlert(t, alertStore, "cmd.rm_rf_root", "high")
	mediumID := mustCreateAlert(t, alertStore, "file.dotenv_access", "medium")
	lowID := mustCreateAlert(t, alertStore, "perf.copy_secret", "low")

	// severity 集合过滤：只捞 medium+，low 不返回
	fetchedList, listErr := alertStore.ListUnnotifiedAlerts(ctx, []string{"medium", "high"}, 10, 100)
	require.NoError(t, listErr)
	require.Len(t, fetchedList, 3, "low 不在 medium+ 集合内")
	for _, alertRow := range fetchedList {
		assert.NotEqual(t, lowID, alertRow.ID)
		assert.Nil(t, alertRow.NotifiedAt, "未通知告警 notified_at 应为空")
		assert.Equal(t, 0, alertRow.NotifyAttempts)
	}

	// created_at 升序：老告警先送（列表首条是最早创建的 high）
	assert.Equal(t, highFirst, fetchedList[0].ID)

	// maxAttempts 排除耗尽重试的行
	attemptErr := alertStore.IncrementAlertNotifyAttempts(ctx, []string{mediumID})
	require.NoError(t, attemptErr)
	exhaustedList, exhaustedErr := alertStore.ListUnnotifiedAlerts(ctx, []string{"medium", "high"}, 1, 100)
	require.NoError(t, exhaustedErr)
	assert.Len(t, exhaustedList, 2, "attempts=1 达上限 1 的行被排除")
}

func TestMarkAlertsNotified(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts")
	alertStore := NewStore(testPool)
	ctx := context.Background()

	firstID := mustCreateAlert(t, alertStore, "dlp.jwt", "high")
	secondID := mustCreateAlert(t, alertStore, "cmd.rm_rf_root", "high")
	_ = mustCreateAlert(t, alertStore, "file.dotenv_access", "medium")

	require.NoError(t, alertStore.MarkAlertsNotified(ctx, []string{firstID, secondID}))

	remainingList, listErr := alertStore.ListUnnotifiedAlerts(ctx, []string{"medium", "high"}, 10, 100)
	require.NoError(t, listErr)
	assert.Len(t, remainingList, 1, "已标记的两条不再被捞出")

	// 重复标记幂等（notified_at IS NULL 条件保护，不会覆盖新时间戳也无需报错）
	require.NoError(t, alertStore.MarkAlertsNotified(ctx, []string{firstID, secondID}))
}

func TestIncrementAlertNotifyAttempts(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts")
	alertStore := NewStore(testPool)
	ctx := context.Background()

	alertID := mustCreateAlert(t, alertStore, "dlp.jwt", "high")

	for attemptRound := 1; attemptRound <= 3; attemptRound++ {
		require.NoError(t, alertStore.IncrementAlertNotifyAttempts(ctx, []string{alertID}))
		fetchedList, listErr := alertStore.ListUnnotifiedAlerts(ctx, []string{"medium", "high"}, attemptRound+1, 100)
		require.NoError(t, listErr)
		assert.Len(t, fetchedList, 1, "attempts=%d 未达上限 %d 仍可捞", attemptRound, attemptRound+1)
	}
	// 达上限后排除
	fetchedList, listErr := alertStore.ListUnnotifiedAlerts(ctx, []string{"medium", "high"}, 3, 100)
	require.NoError(t, listErr)
	assert.Empty(t, fetchedList, "attempts=3 达上限 3 后不再返回")
}
