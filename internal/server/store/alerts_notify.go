package store

import (
	"context"
)

// 告警通知外送的存储侧：捞取未通知告警、标记已通知、累计失败次数。
// 外送语义为 at-least-once：发送成功与标记落库之间进程崩溃会重发，通知场景可接受。

// ListUnnotifiedAlerts 捞取待外送的告警（notified_at 为空且失败次数未达上限），
// 按 created_at 升序（老告警先送）。severities 为外送阈值展开后的集合，
// 调用方必须保证非空——ANY(空数组) 匹配不到任何行，属隐蔽 bug。
func (store *Store) ListUnnotifiedAlerts(ctx context.Context, severities []string, maxAttempts int, limit int) ([]Alert, error) {
	rows, queryErr := store.pool.Query(ctx,
		`SELECT `+alertColumns+` FROM alerts
		 WHERE notified_at IS NULL AND notify_attempts < $1 AND severity = ANY($2)
		 ORDER BY created_at ASC, id ASC LIMIT $3`,
		maxAttempts, severities, limit)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()
	return scanAlertRows(rows)
}

// MarkAlertsNotified 将本批告警标记为已外送；仅更新仍处于未通知状态的行（幂等）。
func (store *Store) MarkAlertsNotified(ctx context.Context, alertIDs []string) error {
	_, execErr := store.pool.Exec(ctx,
		`UPDATE alerts SET notified_at = now()
		 WHERE id = ANY($1::uuid[]) AND notified_at IS NULL`, alertIDs)
	return execErr
}

// IncrementAlertNotifyAttempts 累计本批告警的外送失败次数；
// 达到调用方上限后 ListUnnotifiedAlerts 不再返回这些行。
func (store *Store) IncrementAlertNotifyAttempts(ctx context.Context, alertIDs []string) error {
	_, execErr := store.pool.Exec(ctx,
		`UPDATE alerts SET notify_attempts = notify_attempts + 1 WHERE id = ANY($1::uuid[])`, alertIDs)
	return execErr
}
