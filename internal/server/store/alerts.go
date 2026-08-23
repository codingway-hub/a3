package store

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Alert 对应 alerts 表一行。
type Alert struct {
	ID             string
	DeviceID       string
	SessionKey     string
	EventID        string
	RuleID         string
	RuleName       string
	Severity       string
	Action         string
	Snippet        string
	Summary        string
	Status         string
	CreatedAt      time.Time
	AcknowledgedAt *time.Time
}

// CreateAlert 写入一条告警；id/created_at 由数据库生成后回填，初始状态固定为 open。
func (store *Store) CreateAlert(ctx context.Context, alert *Alert) error {
	return store.pool.QueryRow(ctx,
		`INSERT INTO alerts (device_id, session_key, event_id, rule_id, rule_name, severity, action, snippet, summary)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, status, created_at`,
		alert.DeviceID, alert.SessionKey, alert.EventID, alert.RuleID, alert.RuleName,
		alert.Severity, alert.Action, alert.Snippet, alert.Summary,
	).Scan(&alert.ID, &alert.Status, &alert.CreatedAt)
}

// AcknowledgeAlert 确认处理告警。仅当仍为 open 时更新；重复确认幂等返回成功；
// 记录不存在返回 ErrNotFound。
func (store *Store) AcknowledgeAlert(ctx context.Context, alertID string) error {
	commandTag, err := store.pool.Exec(ctx,
		`UPDATE alerts SET status = 'acknowledged', acknowledged_at = now()
		 WHERE id = $1 AND status = 'open'`, alertID)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() > 0 {
		return nil
	}
	// 未更新：要么已确认（幂等成功），要么不存在
	var exists bool
	existsErr := store.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM alerts WHERE id = $1)`, alertID).Scan(&exists)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

const alertColumns = `id, device_id, session_key, event_id, rule_id, rule_name, severity, action, snippet, summary, status, created_at, acknowledged_at`

// AlertFilter 描述告警列表的筛选条件；空串表示不过滤。
type AlertFilter struct {
	Status   string
	Severity string
	Page     int
	PageSize int
}

// buildAlertWhereClause 组装 status/severity 的过滤子句与绑定参数（ListAlerts 与导出共用）。
func buildAlertWhereClause(statusFilter string, severityFilter string) (whereClause string, queryArgs []any) {
	clauses := []string{"true"}
	if statusFilter != "" {
		queryArgs = append(queryArgs, statusFilter)
		clauses = append(clauses, "status = $"+strconv.Itoa(len(queryArgs)))
	}
	if severityFilter != "" {
		queryArgs = append(queryArgs, severityFilter)
		clauses = append(clauses, "severity = $"+strconv.Itoa(len(queryArgs)))
	}
	for index, clause := range clauses {
		if index > 0 {
			whereClause += " AND "
		}
		whereClause += clause
	}
	return whereClause, queryArgs
}

// ListAlerts 按筛选条件分页返回告警（created_at 倒序），并给出满足条件的总数。
func (store *Store) ListAlerts(ctx context.Context, filter AlertFilter) (list []Alert, totalCount int, err error) {
	page, pageSize := normalizePage(filter.Page, filter.PageSize)
	limit, offset := pageWindow(page, pageSize)

	whereClause, queryArgs := buildAlertWhereClause(filter.Status, filter.Severity)

	countScanErr := store.pool.QueryRow(ctx,
		`SELECT count(*) FROM alerts WHERE `+whereClause, queryArgs...).Scan(&totalCount)
	if countScanErr != nil {
		return nil, 0, countScanErr
	}

	listArgs := append(queryArgs, limit, offset)
	limitOrdinal := "$" + strconv.Itoa(len(listArgs)-1)
	offsetOrdinal := "$" + strconv.Itoa(len(listArgs))
	rows, err := store.pool.Query(ctx,
		`SELECT `+alertColumns+` FROM alerts WHERE `+whereClause+
			` ORDER BY created_at DESC LIMIT `+limitOrdinal+` OFFSET `+offsetOrdinal, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	list, scanAllErr := scanAlertRows(rows)
	return list, totalCount, scanAllErr
}

// alertExportRowHardCap 导出场景的防御性行数上限（远超正常审计规模，仅防失控查询）。
const alertExportRowHardCap = 100000

// ListAlertsForExport 导出场景全量拉取告警：绕过列表分页钳制（normalizePage 上限 100），
// 仅保留防御性硬上限，保证审计取证不静默截断。
func (store *Store) ListAlertsForExport(ctx context.Context, statusFilter string, severityFilter string) ([]Alert, error) {
	whereClause, queryArgs := buildAlertWhereClause(statusFilter, severityFilter)
	rows, err := store.pool.Query(ctx,
		`SELECT `+alertColumns+` FROM alerts WHERE `+whereClause+
			` ORDER BY created_at DESC LIMIT `+strconv.Itoa(alertExportRowHardCap), queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAlertRows(rows)
}

// scanAlertRows 消费告警结果集并逐行扫描。
func scanAlertRows(rows pgx.Rows) ([]Alert, error) {
	alertList := make([]Alert, 0)
	for rows.Next() {
		var alertRow Alert
		if scanErr := rows.Scan(&alertRow.ID, &alertRow.DeviceID, &alertRow.SessionKey, &alertRow.EventID,
			&alertRow.RuleID, &alertRow.RuleName, &alertRow.Severity, &alertRow.Action, &alertRow.Snippet, &alertRow.Summary,
			&alertRow.Status, &alertRow.CreatedAt, &alertRow.AcknowledgedAt); scanErr != nil {
			return nil, scanErr
		}
		alertList = append(alertList, alertRow)
	}
	return alertList, rows.Err()
}

// CountOpenAlerts 统计未处理告警数（概览页统计卡）。
func (store *Store) CountOpenAlerts(ctx context.Context) (int, error) {
	var openCount int
	scanErr := store.pool.QueryRow(ctx,
		`SELECT count(*) FROM alerts WHERE status = 'open'`).Scan(&openCount)
	return openCount, scanErr
}
