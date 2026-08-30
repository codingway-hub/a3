package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Session 对应 sessions 表一行。
type Session struct {
	ID         string
	DeviceID   string
	AgentType  string
	SessionKey string
	Title      string
	StartedAt  time.Time
	EndedAt    time.Time
	EventCount int
	RiskCount  int
	Hostname   string // 关联设备主机名(列表查询 LEFT JOIN devices；设备已删除时为空串)
}

// SessionUpdate 描述一批事件到达后的会话聚合增量。
type SessionUpdate struct {
	DeviceID        string
	SessionKey      string
	AgentType       string
	Title           string
	LastOccurredAt  time.Time
	EventCountDelta int
	RiskCountDelta  int
}

// upsertSessionSQL 会话 upsert 增量聚合（计数累加、ended_at 取较大、title 仅空时补）。
// 供单条路径（UpsertSession）与同事务批路径（InsertEventBatchAndAggregateSessions）复用。
const upsertSessionSQL = `
	INSERT INTO sessions (device_id, session_key, agent_type, title, started_at, ended_at, event_count, risk_count)
	 VALUES ($1, $2, $3, $4, $5, $5, $6, $7)
	 ON CONFLICT (device_id, session_key) DO UPDATE SET
	   event_count = sessions.event_count + EXCLUDED.event_count,
	   risk_count  = sessions.risk_count  + EXCLUDED.risk_count,
	   ended_at    = GREATEST(sessions.ended_at, EXCLUDED.ended_at),
	   title       = CASE WHEN sessions.title = '' AND EXCLUDED.title <> '' THEN EXCLUDED.title ELSE sessions.title END`

// UpsertSession 以单条 upsert 原子完成会话创建或增量聚合：
// 计数累加、ended_at 取较大值、title 仅在现值为空且新值非空时补写。
func (store *Store) UpsertSession(ctx context.Context, update SessionUpdate) error {
	_, err := store.pool.Exec(ctx, upsertSessionSQL,
		update.DeviceID, update.SessionKey, update.AgentType, update.Title,
		update.LastOccurredAt, update.EventCountDelta, update.RiskCountDelta)
	return err
}

// RebuildSessionEventCounts 从 events 全量重算每个会话的事件计数与时间窗，逐行
// upsert 修正历史漂移（事件先落库、计数补充失败的场景）。title 与 risk_count 不覆盖
// （标题留人工/批内补写语义，风险计数由扫描链路逐步累加）。
// 供服务端启动时（监听前）对账调用，之后与告警链路按需增量并存。
func (store *Store) RebuildSessionEventCounts(ctx context.Context) error {
	_, err := store.pool.Exec(ctx,
		`INSERT INTO sessions (device_id, session_key, agent_type, started_at, ended_at, event_count)
		 SELECT event.device_id, event.session_key, event.agent_type,
		        min(event.occurred_at), max(event.occurred_at), count(*)
		   FROM events AS event
		  GROUP BY event.device_id, event.session_key, event.agent_type
		 ON CONFLICT (device_id, session_key) DO UPDATE SET
		   event_count = EXCLUDED.event_count,
		   started_at  = LEAST(sessions.started_at, EXCLUDED.started_at),
		   ended_at    = GREATEST(sessions.ended_at, EXCLUDED.ended_at)`)
	return err
}

const sessionColumns = `id, device_id, agent_type, session_key, title, started_at, ended_at, event_count, risk_count`

// SessionFilter 描述会话列表的检索条件；零值字段表示不过滤。
type SessionFilter struct {
	Keyword     string
	DeviceID    string
	RiskOnly    bool
	StartedFrom *time.Time
	StartedTo   *time.Time
	Page        int
	PageSize    int
}

// buildSessionWhere 依据过滤条件拼装 WHERE 子句与对应参数（$N 序号与参数追加顺序一致）。
// 列名以 s. 限定：列表查询 LEFT JOIN devices 后 device_id 等列存在歧义。
func buildSessionWhere(filter SessionFilter) (whereClause string, args []any) {
	clauses := []string{"true"}
	appendValue := func(value any) string {
		args = append(args, value)
		return "$" + strconv.Itoa(len(args))
	}
	if filter.Keyword != "" {
		keywordPattern := likePatternContains(filter.Keyword)
		clauses = append(clauses, fmt.Sprintf("(s.title ILIKE %s OR s.session_key ILIKE %s)",
			appendValue(keywordPattern), appendValue(keywordPattern)))
	}
	if filter.DeviceID != "" {
		clauses = append(clauses, "s.device_id = "+appendValue(filter.DeviceID))
	}
	if filter.RiskOnly {
		clauses = append(clauses, "s.risk_count > 0")
	}
	if filter.StartedFrom != nil {
		clauses = append(clauses, "s.started_at >= "+appendValue(*filter.StartedFrom))
	}
	if filter.StartedTo != nil {
		clauses = append(clauses, "s.started_at <= "+appendValue(*filter.StartedTo))
	}
	whereClause = ""
	for _, clause := range clauses {
		if whereClause != "" {
			whereClause += " AND "
		}
		whereClause += clause
	}
	return whereClause, args
}

// ListSessions 按过滤条件分页返回会话列表（started_at 倒序），并给出满足条件的总数。
func (store *Store) ListSessions(ctx context.Context, filter SessionFilter) (list []Session, totalCount int, err error) {
	page, pageSize := normalizePage(filter.Page, filter.PageSize)
	limit, offset := pageWindow(page, pageSize)

	whereClause, args := buildSessionWhere(filter)

	countScanErr := store.pool.QueryRow(ctx,
		`SELECT count(*) FROM sessions AS s WHERE `+whereClause, args...).Scan(&totalCount)
	if countScanErr != nil {
		return nil, 0, countScanErr
	}

	listArgs := append(args, limit, offset)
	limitOrdinal := "$" + strconv.Itoa(len(listArgs)-1)
	offsetOrdinal := "$" + strconv.Itoa(len(listArgs))
	rows, err := store.pool.Query(ctx,
		`SELECT s.id, s.device_id, s.agent_type, s.session_key, s.title, s.started_at, s.ended_at,
		        s.event_count, s.risk_count, COALESCE(d.hostname, '')
		 FROM sessions AS s LEFT JOIN devices AS d ON d.device_id = s.device_id
		 WHERE `+whereClause+
			` ORDER BY s.started_at DESC LIMIT `+limitOrdinal+` OFFSET `+offsetOrdinal, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	list = make([]Session, 0)
	for rows.Next() {
		var session Session
		if scanErr := rows.Scan(&session.ID, &session.DeviceID, &session.AgentType, &session.SessionKey,
			&session.Title, &session.StartedAt, &session.EndedAt, &session.EventCount, &session.RiskCount,
			&session.Hostname); scanErr != nil {
			return nil, 0, scanErr
		}
		list = append(list, session)
	}
	return list, totalCount, rows.Err()
}

// GetSession 按设备+会话键取单个会话，未命中返回 ErrNotFound。
func (store *Store) GetSession(ctx context.Context, deviceID string, sessionKey string) (*Session, error) {
	var session Session
	scanErr := store.pool.QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE device_id = $1 AND session_key = $2`,
		deviceID, sessionKey,
	).Scan(&session.ID, &session.DeviceID, &session.AgentType, &session.SessionKey,
		&session.Title, &session.StartedAt, &session.EndedAt, &session.EventCount, &session.RiskCount)
	if errors.Is(scanErr, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if scanErr != nil {
		return nil, scanErr
	}
	return &session, nil
}

// CountSessions 返回会话总数与含风险会话数（概览页统计卡）。
func (store *Store) CountSessions(ctx context.Context) (totalCount int, riskyCount int, err error) {
	scanErr := store.pool.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE risk_count > 0) FROM sessions`).Scan(&totalCount, &riskyCount)
	return totalCount, riskyCount, scanErr
}
