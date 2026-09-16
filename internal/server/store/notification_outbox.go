package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// 告警通知 outbox 的存储侧：领取到期通知、标记投递结果。
//
// 领取语义（可靠链路的并发关键）：
//   - 领取在单事务内 SELECT ... FOR UPDATE OF n SKIP LOCKED，随后把行置为 sending，
//     提交后外送。多 worker 并发互不抢同一行（SKIP LOCKED）；
//   - 外送成功/失败后按 id 条件更新（仅限自己持有的 sending 行），幂等；
//   - sending 行超过静默期（领取方崩溃/进程重启）视为孤儿，由领取查询回收重发：
//     at-least-once 且进程重启无损。
// 去重依赖 dedup_key 唯一约束：同一告警至多一条通知行。

// Notification 一条待投递/投递中的通知：outbox 行 + 关联告警数据。
type Notification struct {
	ID       string
	Attempts int
	Alert    Alert
}

// notificationAlertColumns 领取查询关联告警所需的告警列（不含 outbox 状态列）。
const notificationAlertColumns = `a.id, a.device_id, a.session_key, a.event_id, a.rule_id, a.rule_name, a.severity, a.action, a.snippet, a.summary, a.status, a.created_at, a.acknowledged_at`

// claimSendingStaleAfter sending 孤儿回收的静默期：领取方崩溃后，行停留在 sending，
// 超过此刻距最近心跳则被回收重投。
const claimSendingStaleAfter = 10 * time.Minute

// enqueueNotification 在告警落库事务内为一条告警登记通知。
// dedup_key 取告警 ID，唯一约束保证同一告警至多入队一次（去重）。在告警落库的
// 同一事务里调用（ApplyScanOutcome / CreateAlert），实现「告警在 → 通知在」。
func enqueueNotification(ctx context.Context, tx pgx.Tx, alertID string) error {
	// dedup_key(text) 与 alert_id(uuid) 类型不同，须分开占位符避免 PG
	// 「inconsistent types deduced for parameter」报错（42P08）。
	_, execErr := tx.Exec(ctx,
		`INSERT INTO notification_outbox (dedup_key, alert_id, created_at, updated_at)
		 VALUES ($1, $2, now(), now())
		 ON CONFLICT (dedup_key) DO NOTHING`, alertID, alertID)
	return execErr
}

// ClaimDueNotifications 在单事务内领取一批到期待投递的通知（含关联告警数据），
// 并把它们置为 sending：pending/failed 且 next_attempt_at 已到，或 sending 超时孤儿。
// severities 为外送阈值展开后的集合，调用方保证非空——ANY(空数组) 匹配不到行。
// 返回的行由调用方负责 MarkNotificationsSent/Failed；未标记的行会在孤儿窗口后重投。
func (store *Store) ClaimDueNotifications(ctx context.Context, severities []string, maxAttempts int, limit int) ([]Notification, error) {
	tx, beginErr := store.pool.Begin(ctx)
	if beginErr != nil {
		return nil, beginErr
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, queryErr := tx.Query(ctx,
		`SELECT n.id, n.attempts, `+notificationAlertColumns+`
		   FROM notification_outbox n
		   JOIN alerts a ON a.id = n.alert_id
		  WHERE ( (n.status IN ('pending', 'failed') AND n.next_attempt_at <= now())
		           OR (n.status = 'sending' AND n.updated_at < now() - ($4::double precision * interval '1 second')) )
		    AND n.attempts < $1::int
		    AND a.severity = ANY($2::text[])
		  ORDER BY n.next_attempt_at ASC, n.created_at ASC
		  LIMIT $3::int
		   FOR UPDATE OF n SKIP LOCKED`,
		maxAttempts, severities, limit, claimSendingStaleAfter.Seconds())
	if queryErr != nil {
		return nil, queryErr
	}

	claimed := make([]Notification, 0, limit)
	for rows.Next() {
		var notification Notification
		if scanErr := rows.Scan(&notification.ID, &notification.Attempts,
			&notification.Alert.ID, &notification.Alert.DeviceID, &notification.Alert.SessionKey,
			&notification.Alert.EventID, &notification.Alert.RuleID, &notification.Alert.RuleName,
			&notification.Alert.Severity, &notification.Alert.Action, &notification.Alert.Snippet,
			&notification.Alert.Summary, &notification.Alert.Status, &notification.Alert.CreatedAt,
			&notification.Alert.AcknowledgedAt); scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		claimed = append(claimed, notification)
	}
	rows.Close()
	if closeErr := rows.Err(); closeErr != nil {
		return nil, closeErr
	}

	if len(claimed) > 0 {
		claimedIDs := make([]string, len(claimed))
		for index, notification := range claimed {
			claimedIDs[index] = notification.ID
		}
		if _, updateErr := tx.Exec(ctx,
			`UPDATE notification_outbox SET status = 'sending', updated_at = now()
			  WHERE id = ANY($1::uuid[])`, claimedIDs); updateErr != nil {
			return nil, updateErr
		}
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return nil, commitErr
	}
	return claimed, nil
}

// MarkNotificationsSent 把已成功外送的通知标记为 sent（attempts + 1、记录 sent_at）。
// 仅更新仍处于 sending 的行——领取方崩溃后被孤儿回收重投的旧行不受影响（幂等）。
func (store *Store) MarkNotificationsSent(ctx context.Context, notificationIDs []string) error {
	_, execErr := store.pool.Exec(ctx,
		`UPDATE notification_outbox
		    SET status = 'sent', attempts = attempts + 1, sent_at = now(), updated_at = now()
		  WHERE id = ANY($1::uuid[]) AND status = 'sending'`, notificationIDs)
	return execErr
}

// MarkNotificationsFailed 累计本次失败：attempts + 1，按退避推后 next_attempt_at；
// 下次尝试数达到 maxAttempts 则置 dropped（坏地址自然老化，永久停止重试）。
// lastError 截断到 512 字节，防异常 URL 撑爆行宽。
func (store *Store) MarkNotificationsFailed(ctx context.Context, notificationIDs []string, lastError string, nextAttemptDelay time.Duration, maxAttempts int) error {
	if len(lastError) > 512 {
		lastError = lastError[:512]
	}
	_, execErr := store.pool.Exec(ctx,
		`UPDATE notification_outbox
		    SET status = CASE WHEN attempts + 1 >= $2 THEN 'dropped' ELSE 'failed' END,
		        attempts = attempts + 1,
		        last_error = $3,
		        next_attempt_at = now() + ($4 * interval '1 second'),
		        updated_at = now()
		  WHERE id = ANY($1::uuid[]) AND status = 'sending'`,
		notificationIDs, maxAttempts, lastError, nextAttemptDelay.Seconds())
	return execErr
}