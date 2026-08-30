package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// EventRow 对应 events 表一行；PayloadJSON 为完整事件 JSON，RiskTagsJSON 为风险标签数组 JSON。
type EventRow struct {
	EventID      string
	DeviceID     string
	SessionKey   string
	AgentType    string
	EventType    string
	Role         string
	OccurredAt   time.Time
	PayloadJSON  []byte
	RiskTagsJSON []byte
}

// InsertEvents 批量写入事件，返回与入参等长的接受标记数组（true=本次新插入）。
//
// 以 (device_id, event_id) 复合主键做 ON CONFLICT DO NOTHING：设备内重复上报
// （终端重试/断网重放）标记为 false；跨设备同 event_id 各自落库，互不吞并。
// 整批包裹在一个事务里——中途失败全部回滚，调用方整批重试即可（幂等安全）。
func (store *Store) InsertEvents(ctx context.Context, rows []EventRow) (acceptedFlags []bool, err error) {
	if len(rows) == 0 {
		return nil, nil
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = errors.Join(err, rollbackErr)
		}
	}()

	acceptedFlags = make([]bool, len(rows))
	for rowIndex, row := range rows {
		insertedID := ""
		scanErr := tx.QueryRow(ctx,
			`INSERT INTO events (event_id, device_id, session_key, agent_type, event_type, role, occurred_at, payload, risk_tags)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (device_id, event_id) DO NOTHING
			 RETURNING event_id`,
			row.EventID, row.DeviceID, row.SessionKey, row.AgentType, row.EventType, row.Role,
			row.OccurredAt, row.PayloadJSON, row.RiskTagsJSON,
		).Scan(&insertedID)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			continue // 冲突去重，不计入 accepted
		}
		if scanErr != nil {
			return nil, scanErr
		}
		acceptedFlags[rowIndex] = true
	}
	return acceptedFlags, tx.Commit(ctx)
}

// InsertEventBatchAndAggregateSessions 单事务内完成事件插入与会话计数聚合：
// 逐条 INSERT（复合键 ON CONFLICT DO NOTHING），仅对实际接受的行累加会话计数，
// 再以 sessionMetas 提供的 agent_type/title/时间戳 upsert 会话（title 仅空时补、
// ended_at 取较大；接受数为 0 的会话跳过）。
//
// 事件落库与会话计数同生共死：任一环节失败整批回滚，根除原先 InsertEvents 与
// UpsertSession 分离事务造成的计数永久漂移。accepted 返回给上层做异步风险扫描。
func (store *Store) InsertEventBatchAndAggregateSessions(ctx context.Context,
	rows []EventRow, sessionMetas []SessionUpdate) (acceptedFlags []bool, err error) {

	if len(rows) == 0 {
		return []bool{}, nil
	}
	tx, beginErr := store.pool.Begin(ctx)
	if beginErr != nil {
		return nil, beginErr
	}
	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = errors.Join(err, rollbackErr)
		}
	}()

	acceptedFlags = make([]bool, len(rows))
	acceptedBySession := map[string]int{}
	for rowIndex, row := range rows {
		insertedID := ""
		scanErr := tx.QueryRow(ctx,
			`INSERT INTO events (event_id, device_id, session_key, agent_type, event_type, role, occurred_at, payload, risk_tags)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (device_id, event_id) DO NOTHING
			 RETURNING event_id`,
			row.EventID, row.DeviceID, row.SessionKey, row.AgentType, row.EventType, row.Role,
			row.OccurredAt, row.PayloadJSON, row.RiskTagsJSON,
		).Scan(&insertedID)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			continue // 冲突去重，不计入 accepted
		}
		if scanErr != nil {
			return nil, scanErr
		}
		acceptedFlags[rowIndex] = true
		acceptedBySession[row.SessionKey]++
	}

	for _, sessionMeta := range sessionMetas {
		delta := acceptedBySession[sessionMeta.SessionKey]
		if delta == 0 {
			continue
		}
		if _, upsertErr := tx.Exec(ctx, upsertSessionSQL,
			sessionMeta.DeviceID, sessionMeta.SessionKey, sessionMeta.AgentType,
			sessionMeta.Title, sessionMeta.LastOccurredAt, delta, 0); upsertErr != nil {
			return nil, upsertErr
		}
	}
	return acceptedFlags, tx.Commit(ctx)
}

// ListUnscannedEvents 分页列出尚未扫描的事件行（含完整 payload），按发生时间升序。
// 供告警中心启动补扫与周期对账使用：因队列满丢弃、进程重启丢内存队列等原因
// 错过实时扫描的事件仍完整保留在库中，从这里捞回即可补扫，保证审计无损。
func (store *Store) ListUnscannedEvents(ctx context.Context, limit int) ([]EventRow, error) {
	rows, queryErr := store.pool.Query(ctx,
		`SELECT event_id, device_id, session_key, agent_type, event_type, role, occurred_at, payload, risk_tags
		 FROM events WHERE scanned_at IS NULL
		 ORDER BY occurred_at ASC, event_id ASC LIMIT $1`, limit)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	unscannedEvents := make([]EventRow, 0)
	for rows.Next() {
		var row EventRow
		if scanErr := rows.Scan(&row.EventID, &row.DeviceID, &row.SessionKey, &row.AgentType,
			&row.EventType, &row.Role, &row.OccurredAt, &row.PayloadJSON, &row.RiskTagsJSON); scanErr != nil {
			return nil, scanErr
		}
		unscannedEvents = append(unscannedEvents, row)
	}
	return unscannedEvents, rows.Err()
}

// ListEventsBySession 返回某设备某会话的全部事件（回放流），按发生时间升序。
func (store *Store) ListEventsBySession(ctx context.Context, deviceID string, sessionKey string) ([]EventRow, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT event_id, device_id, session_key, agent_type, event_type, role, occurred_at, payload, risk_tags
		 FROM events WHERE device_id = $1 AND session_key = $2 ORDER BY occurred_at ASC`,
		deviceID, sessionKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]EventRow, 0)
	for rows.Next() {
		var row EventRow
		if scanErr := rows.Scan(&row.EventID, &row.DeviceID, &row.SessionKey, &row.AgentType, &row.EventType,
			&row.Role, &row.OccurredAt, &row.PayloadJSON, &row.RiskTagsJSON); scanErr != nil {
			return nil, scanErr
		}
		events = append(events, row)
	}
	return events, rows.Err()
}

// CountEventsSince 统计指定时刻之后的事件数（概览页"今日事件数"）。
func (store *Store) CountEventsSince(ctx context.Context, since time.Time) (int, error) {
	var eventCount int
	scanErr := store.pool.QueryRow(ctx,
		`SELECT count(*) FROM events WHERE occurred_at >= $1`, since).Scan(&eventCount)
	return eventCount, scanErr
}
