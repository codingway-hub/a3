// scan.go 服务端规则扫描的无损化落点：未扫描事件的捞取与扫描结果的原子应用。
//
// 无损闭环由三块拼成：
//  1. 事件落库在先（InsertEvents），扫描进度在后（scanned_at）——素材永远在库；
//  2. ApplyScanOutcome 以「条件更新 events」为唯一入口，实时队列与补扫对账
//     并发命中同一事件时至多一方产生告警副作用（至多一次告警）；
//  3. 告警中心按 scanned_at IS NULL 周期对账，把队列满丢弃/重启丢队列/
//     引擎未就绪失败等造成的漏扫积压捞回补扫（最终无损）。
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ScanOutcome 描述一条事件的完整扫描结果：风险标签 JSON、待落地告警与会话聚合增量。
type ScanOutcome struct {
	EventID       string
	RiskTagsJSON  []byte
	Alerts        []*Alert
	SessionUpdate SessionUpdate
}

// ApplyScanOutcome 在单事务内原子应用一条事件的扫描结果：条件更新 events（仅当
// 尚未扫描）→ 回写 risk_tags → 落告警 → 会话风险计数，四步同生共死。
// 返回 applied=false 表示事件已被其他路径抢先处理，本次结果整体放弃。
//
// SQL 与 UpsertSession/CreateAlert 保持同构；不复用它们是因为这里必须与
// 条件更新 events 同处一个事务才能保证「要么全部生效、要么全部不发生」。
func (store *Store) ApplyScanOutcome(ctx context.Context, outcome ScanOutcome) (applied bool, err error) {
	tx, beginErr := store.pool.Begin(ctx)
	if beginErr != nil {
		return false, beginErr
	}
	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = errors.Join(err, rollbackErr)
		}
	}()

	commandTag, execErr := tx.Exec(ctx,
		`UPDATE events SET risk_tags = $2, scanned_at = now() WHERE event_id = $1 AND scanned_at IS NULL`,
		outcome.EventID, outcome.RiskTagsJSON)
	if execErr != nil {
		return false, execErr
	}
	if commandTag.RowsAffected() == 0 {
		return false, nil // 已被抢先处理（重复投递或补扫竞速）：整批放弃
	}

	for _, alertToCreate := range outcome.Alerts {
		if _, insertErr := tx.Exec(ctx,
			`INSERT INTO alerts (device_id, session_key, event_id, rule_id, rule_name, severity, action, snippet, summary)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			alertToCreate.DeviceID, alertToCreate.SessionKey, alertToCreate.EventID, alertToCreate.RuleID,
			alertToCreate.RuleName, alertToCreate.Severity, alertToCreate.Action,
			alertToCreate.Snippet, alertToCreate.Summary); insertErr != nil {
			return false, insertErr
		}
	}

	sessionUpdate := outcome.SessionUpdate
	if _, upsertErr := tx.Exec(ctx,
		`INSERT INTO sessions (device_id, session_key, agent_type, title, started_at, ended_at, event_count, risk_count)
		 VALUES ($1, $2, $3, $4, $5, $5, $6, $7)
		 ON CONFLICT (device_id, session_key) DO UPDATE SET
		   event_count = sessions.event_count + EXCLUDED.event_count,
		   risk_count  = sessions.risk_count  + EXCLUDED.risk_count,
		   ended_at    = GREATEST(sessions.ended_at, EXCLUDED.ended_at),
		   title       = CASE WHEN sessions.title = '' AND EXCLUDED.title <> '' THEN EXCLUDED.title ELSE sessions.title END`,
		sessionUpdate.DeviceID, sessionUpdate.SessionKey, sessionUpdate.AgentType, sessionUpdate.Title,
		sessionUpdate.LastOccurredAt, sessionUpdate.EventCountDelta, sessionUpdate.RiskCountDelta); upsertErr != nil {
		return false, upsertErr
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return false, commitErr
	}
	return true, nil
}
