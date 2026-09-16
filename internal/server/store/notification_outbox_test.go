package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// alertForNotify 构造一条待入库告警。
func alertForNotify(ruleID string, severity string) *Alert {
	return &Alert{
		DeviceID: "dev-notify", SessionKey: "sess-notify", EventID: "evt-" + ruleID,
		RuleID: ruleID, RuleName: "规则-" + ruleID, Severity: severity, Action: "block",
		Snippet: "s", Summary: "sm",
	}
}

// outboxStatusFor 直查 outbox 行快照（同包测未公开存取层）。
func outboxStatusFor(t *testing.T, notifyStore *Store, alertID string) (string, int, time.Time) {
	t.Helper()
	var status string
	var attempts int
	var nextAttemptAt time.Time
	scanErr := notifyStore.pool.QueryRow(context.Background(),
		`SELECT status, attempts, next_attempt_at FROM notification_outbox WHERE alert_id = $1`, alertID).
		Scan(&status, &attempts, &nextAttemptAt)
	require.NoError(t, scanErr)
	return status, attempts, nextAttemptAt
}

// TestCreateAlertEnqueuesOutboxAndDedups 告警落库即同事务入队通知；同一告警重复入队
// 被唯一 dedup_key 吸收（去重）。
func TestCreateAlertEnqueuesOutboxAndDedups(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts")
	notifyStore := NewStore(testPool)
	ctx := context.Background()

	alertRow := alertForNotify("dlp.jwt", "high")
	require.NoError(t, notifyStore.CreateAlert(ctx, alertRow))
	require.NotEmpty(t, alertRow.ID)

	status, attempts, _ := outboxStatusFor(t, notifyStore, alertRow.ID)
	assert.Equal(t, "pending", status, "新告警通知以 pending 入队")
	assert.Equal(t, 0, attempts)

	// 模拟告警重建路径的重复入队：ON CONFLICT DO NOTHING 吸收，仍只有一行
	tx, beginErr := notifyStore.pool.Begin(ctx)
	require.NoError(t, beginErr)
	require.NoError(t, enqueueNotification(ctx, tx, alertRow.ID))
	require.NoError(t, tx.Commit(ctx))

	var outboxCount int
	require.NoError(t, notifyStore.pool.QueryRow(ctx,
		`SELECT count(*) FROM notification_outbox WHERE alert_id = $1`, alertRow.ID).Scan(&outboxCount))
	assert.Equal(t, 1, outboxCount, "同一告警至多一条通知")
}

// TestClaimDueNotificationsClaimAndOrphanReclaim 领取置 sending、sending 超时孤儿可回收。
func TestClaimDueNotificationsClaimAndOrphanReclaim(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts")
	notifyStore := NewStore(testPool)
	ctx := context.Background()

	alertRow := alertForNotify("cmd.rm_rf_root", "high")
	require.NoError(t, notifyStore.CreateAlert(ctx, alertRow))

	claimed, claimErr := notifyStore.ClaimDueNotifications(ctx, []string{"high"}, 10, 10)
	require.NoError(t, claimErr)
	require.Len(t, claimed, 1)
	assert.Equal(t, alertRow.ID, claimed[0].Alert.ID)
	assert.Equal(t, 0, claimed[0].Attempts)
	claimedStatus, _, _ := outboxStatusFor(t, notifyStore, alertRow.ID)
	assert.Equal(t, "sending", claimedStatus, "领取即置 sending，防多副本重复投递")

	// 未超时的 sending 行不可再领取
	assert.Empty(t, mustClaimNotifications(t, notifyStore, 10, 10))

	// 领取方崩溃（sending 悬挂超 10min）→ 孤儿可回收重投
	_, execErr := notifyStore.pool.Exec(ctx,
		`UPDATE notification_outbox SET updated_at = now() - interval '11 minutes' WHERE alert_id = $1`, alertRow.ID)
	require.NoError(t, execErr)
	reclaimed, reclaimErr := notifyStore.ClaimDueNotifications(ctx, []string{"high"}, 10, 10)
	require.NoError(t, reclaimErr)
	require.Len(t, reclaimed, 1, "sending 孤儿由领取查询回收")
}

// TestMarkNotificationsSentAndFailed 外送结果落库：成功置 sent，失败累计并退避/封顶 dropped。
func TestMarkNotificationsSentAndFailed(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts")
	notifyStore := NewStore(testPool)
	ctx := context.Background()

	sentAlert := alertForNotify("dlp.jwt", "high")
	require.NoError(t, notifyStore.CreateAlert(ctx, sentAlert))
	sentClaim := mustClaimNotifications(t, notifyStore, 10, 10)
	require.Len(t, sentClaim, 1)
	sentIDs := []string{sentClaim[0].ID}
	require.NoError(t, notifyStore.MarkNotificationsSent(ctx, sentIDs))
	status, attempts, _ := outboxStatusFor(t, notifyStore, sentAlert.ID)
	assert.Equal(t, "sent", status)
	assert.Equal(t, 1, attempts)

	failedAlert := alertForNotify("cmd.rm_rf_root", "high")
	require.NoError(t, notifyStore.CreateAlert(ctx, failedAlert))
	failedClaim := mustClaimNotifications(t, notifyStore, 10, 10)
	require.Len(t, failedClaim, 1)
	failedIDs := []string{failedClaim[0].ID}
	require.NoError(t, notifyStore.MarkNotificationsFailed(ctx, failedIDs, "boom: 599", time.Minute, 2))
	status, attempts, nextAttemptAt := outboxStatusFor(t, notifyStore, failedAlert.ID)
	assert.Equal(t, "failed", status, "未达上限保持 failed 可重试")
	assert.Equal(t, 1, attempts)
	assert.True(t, nextAttemptAt.After(time.Now()), "退避推后下次尝试")

	// 达上限 → dropped：失败行经退避到期→重新领取(sending)后再次失败才累计
	_, execErr := notifyStore.pool.Exec(ctx,
		`UPDATE notification_outbox SET next_attempt_at = now() - interval '1 second' WHERE alert_id = $1`, failedAlert.ID)
	require.NoError(t, execErr)
	reclaimedFailed := mustClaimNotifications(t, notifyStore, 2, 10)
	require.Len(t, reclaimedFailed, 1)
	require.NoError(t, notifyStore.MarkNotificationsFailed(ctx, []string{reclaimedFailed[0].ID}, "boom again", time.Minute, 2))
	status, attempts, _ = outboxStatusFor(t, notifyStore, failedAlert.ID)
	assert.Equal(t, "dropped", status)
	assert.Equal(t, 2, attempts)

	// 长错误截断到 512 字节（失败标记仅作用于 sending 行，另造一条）
	longErrorAlert := alertForNotify("rule.long", "high")
	require.NoError(t, notifyStore.CreateAlert(ctx, longErrorAlert))
	longErrorClaim := mustClaimNotifications(t, notifyStore, 10, 10)
	require.Len(t, longErrorClaim, 1)
	longError := strings.Repeat("e", 2048) // 合法 UTF-8 长串，验证 512 字节截断
	require.NoError(t, notifyStore.MarkNotificationsFailed(ctx, []string{longErrorClaim[0].ID}, longError, time.Minute, 10))
	var truncated string
	require.NoError(t, notifyStore.pool.QueryRow(ctx,
		`SELECT last_error FROM notification_outbox WHERE id = $1`, longErrorClaim[0].ID).Scan(&truncated))
	assert.True(t, len(truncated) <= 512, "错误信息需截断防行宽膨胀")
}

// TestClaimDueNotificationsFilters severities/attempts 门槛与退避中的 failed 不入列。
func TestClaimDueNotificationsFilters(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts")
	notifyStore := NewStore(testPool)
	ctx := context.Background()

	lowAlert := alertForNotify("rule.low", "low")
	require.NoError(t, notifyStore.CreateAlert(ctx, lowAlert))

	highAlert := alertForNotify("rule.high", "high")
	require.NoError(t, notifyStore.CreateAlert(ctx, highAlert))

	// severity 门槛：只领 high
	claimed := mustClaimNotifications(t, notifyStore, 10, 10)
	require.Len(t, claimed, 1)
	assert.Equal(t, highAlert.ID, claimed[0].Alert.ID)

	// 造一条退避中的 failed：推后 next_attempt_at，不 due
	require.NoError(t, notifyStore.MarkNotificationsFailed(ctx, []string{claimed[0].ID}, "down", time.Hour, 10))
	assert.Empty(t, mustClaimNotifications(t, notifyStore, 10, 10), "退避中的 failed 不 in 领取窗口")
}

// mustClaimNotifications 便捷领取（severities 固定 high）。
func mustClaimNotifications(t *testing.T, notifyStore *Store, maxAttempts int, limit int) []Notification {
	t.Helper()
	claimed, claimErr := notifyStore.ClaimDueNotifications(context.Background(), []string{"high"}, maxAttempts, limit)
	require.NoError(t, claimErr)
	return claimed
}