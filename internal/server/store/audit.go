package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// 控制台敏感操作审计：action 与 target_type 的合法取值（与迁移 0008/0010 的 CHECK 约束同源）。
const (
	AuditActionRuleCreate     = "rule_create"
	AuditActionRuleUpdate     = "rule_update"
	AuditActionRulePatch      = "rule_patch"
	AuditActionRuleDelete     = "rule_delete"
	AuditActionDeviceRevoke   = "device_revoke"
	AuditActionDeviceRestore  = "device_restore"
	AuditActionUserCreate     = "user_create"
	AuditActionUserUpdate     = "user_update"

	AuditActionUserPasswordReset = "user_password_reset"

	// AuditActionDeviceTokenRotate 管理员批准的设备 Token 轮换（重复注册不再
	// 无条件换发——唯一换发通道，须人工批准并留痕）。
	AuditActionDeviceTokenRotate = "device_token_rotate"

	// AuditActionCredentialCreate / AuditActionCredentialRevoke 安装凭据（注册门禁）
	// 的生成与吊销。
	AuditActionCredentialCreate = "credential_create"
	AuditActionCredentialRevoke = "credential_revoke"

	auditTargetRule   = "rule"
	auditTargetDevice = "device"

	// AuditTargetUser 用户账号类审计的目标类型（api 层用户管理留痕用）。
	AuditTargetUser = "user"

	// AuditTargetCredential 安装凭据类审计的目标类型（api 层凭据管理留痕用）。
	AuditTargetCredential = "credential"
)

// AuditEntry 对应 audit_log 表一行；Before/After 为变更前后 JSONB 快照原文。
type AuditEntry struct {
	ID         int64
	Action     string
	TargetType string
	TargetID   string
	Operator   string
	Before     []byte
	After      []byte
	CreatedAt  time.Time
}

const auditColumns = `id, action, target_type, target_id, operator, before_state, after_state, created_at`

// AuditFilter 控制审计日志查询的分页与目标过滤（目标过滤可省略）。
type AuditFilter struct {
	TargetType string
	TargetID   string
	Page       int
	PageSize   int
}

// withTx 在单事务内执行业务写与审计写；业务失败回滚连带审计，成功才提交。
func (store *Store) withTx(ctx context.Context, txFunc func(tx pgx.Tx) error) error {
	tx, beginErr := store.pool.Begin(ctx)
	if beginErr != nil {
		return beginErr
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if txFuncErr := txFunc(tx); txFuncErr != nil {
		return txFuncErr
	}
	return tx.Commit(ctx)
}

// appendAuditInTx 在既有事务内追加一条审计记录；快照由调用方序列化，可缺省。
func appendAuditInTx(ctx context.Context, tx pgx.Tx,
	action string, targetType string, targetID string, operator string,
	before []byte, after []byte) error {

	_, execErr := tx.Exec(ctx,
		`INSERT INTO audit_log (action, target_type, target_id, operator, before_state, after_state)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		action, targetType, targetID, operator, before, after)
	return execErr
}

// AppendAudit 独立事务追加一条审计记录（业务写走 WithAudit 事务方法时无需调用本方法）。
func (store *Store) AppendAudit(ctx context.Context,
	action string, targetType string, targetID string, operator string,
	before []byte, after []byte) error {

	return store.withTx(ctx, func(tx pgx.Tx) error {
		return appendAuditInTx(ctx, tx, action, targetType, targetID, operator, before, after)
	})
}

// buildAuditWhereClause 组装 target_type/target_id 的过滤子句与绑定参数。
func buildAuditWhereClause(targetType string, targetID string) (whereClause string, queryArgs []any) {
	clauses := []string{"true"}
	if targetType != "" {
		queryArgs = append(queryArgs, targetType)
		clauses = append(clauses, "target_type = $"+strconv.Itoa(len(queryArgs)))
	}
	if targetID != "" {
		queryArgs = append(queryArgs, targetID)
		clauses = append(clauses, "target_id = $"+strconv.Itoa(len(queryArgs)))
	}
	for index, clause := range clauses {
		if index > 0 {
			whereClause += " AND "
		}
		whereClause += clause
	}
	return whereClause, queryArgs
}

// ListAuditLog 按筛选条件分页返回审计记录（created_at 倒序），并给出满足条件的总数。
func (store *Store) ListAuditLog(ctx context.Context, filter AuditFilter) ([]AuditEntry, int, error) {
	page, pageSize := normalizePage(filter.Page, filter.PageSize)
	limit, offset := pageWindow(page, pageSize)

	whereClause, queryArgs := buildAuditWhereClause(filter.TargetType, filter.TargetID)

	var totalCount int
	countScanErr := store.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE `+whereClause, queryArgs...).Scan(&totalCount)
	if countScanErr != nil {
		return nil, 0, countScanErr
	}

	listArgs := append(queryArgs, limit, offset)
	limitOrdinal := "$" + strconv.Itoa(len(listArgs)-1)
	offsetOrdinal := "$" + strconv.Itoa(len(listArgs))
	rows, queryErr := store.pool.Query(ctx,
		`SELECT `+auditColumns+` FROM audit_log WHERE `+whereClause+
			` ORDER BY id DESC LIMIT `+limitOrdinal+` OFFSET `+offsetOrdinal, listArgs...)
	if queryErr != nil {
		return nil, 0, queryErr
	}
	defer rows.Close()

	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var entry AuditEntry
		if scanErr := rows.Scan(&entry.ID, &entry.Action, &entry.TargetType, &entry.TargetID,
			&entry.Operator, &entry.Before, &entry.After, &entry.CreatedAt); scanErr != nil {
			return nil, 0, scanErr
		}
		entries = append(entries, entry)
	}
	return entries, totalCount, rows.Err()
}

// deviceStatusAuditAction 设备状态 → 审计动作映射；非吊销/恢复语义的状态返回 false。
func deviceStatusAuditAction(status string) (string, bool) {
	if status == "revoked" {
		return AuditActionDeviceRevoke, true
	}
	if status == "active" {
		return AuditActionDeviceRestore, true
	}
	return "", false
}

// SetDeviceStatusWithAudit 更新设备状态并同事务落 device_revoke/device_restore 审计
// （before/after 为 {status: ...} 快照）；行不存在返回 ErrNotFound，无留痕。
func (store *Store) SetDeviceStatusWithAudit(ctx context.Context, deviceID string, status string, operator string) error {
	auditAction, isAuditable := deviceStatusAuditAction(status)
	if !isAuditable {
		// 表层 status 由控制台 handler 收敛为 revoked/active；防御式兜底直写不留痕
		return store.SetDeviceStatus(ctx, deviceID, status)
	}
	return store.withTx(ctx, func(tx pgx.Tx) error {
		var beforeStatus string
		scanErr := tx.QueryRow(ctx,
			`SELECT status FROM devices WHERE device_id = $1 FOR UPDATE`, deviceID).Scan(&beforeStatus)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if scanErr != nil {
			return scanErr
		}
		commandTag, execErr := tx.Exec(ctx,
			`UPDATE devices SET status = $2 WHERE device_id = $1`, deviceID, status)
		if execErr != nil {
			return execErr
		}
		if commandTag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return appendAuditInTx(ctx, tx, auditAction, auditTargetDevice, deviceID, operator,
			[]byte(`{"status":"`+beforeStatus+`"}`), []byte(`{"status":"`+status+`"}`))
	})
}
