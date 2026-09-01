package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// 安装凭据（注册门禁）数据层：管理员生成一次性接入代码，注册端点原子消费。
// 明文代码仅生成时返回一次，表中只存 SHA-256 摘要（code_hash）；使用结果写入
// install_credential_uses（成功 / 过期 / 停用 / 用量用尽 / 无效 / 限流）供追溯。

// CredentialOutcome 注册凭据消费结果分类（与迁移 0011 的 CHECK 取值同源）。
const (
	CredentialOutcomeSuccess          = "success"
	CredentialOutcomeRejectedExpired  = "rejected_expired"
	CredentialOutcomeRejectedDisabled = "rejected_disabled"
	CredentialOutcomeRejectedUsed     = "rejected_used"
	CredentialOutcomeRejectedInvalid  = "rejected_invalid"
	CredentialOutcomeRateLimited      = "rate_limited"
)

// InstallCredential 对应 install_credentials 表一行（列表展示形态，不含明文代码）。
type InstallCredential struct {
	ID        int64
	CodeHint  string // code_hash 前 8 位，供控制台区分展示
	Scope     string
	ExpiresAt time.Time
	MaxUses   int
	UsesCount int
	Enabled   bool
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CredentialUse 对应 install_credential_uses 表一行。
type CredentialUse struct {
	ID           int64
	CredentialID *int64
	Outcome      string
	DeviceID     string
	ClientIP     string
	CreatedAt    time.Time
}

// CreateInstallCredentialWithAudit 生成安装凭据并同事务落 credential_create 审计。
// 明文代码由调用方生成后仅保存摘要；同名（哈希）冲突返回 ErrAlreadyExists。
func (store *Store) CreateInstallCredentialWithAudit(ctx context.Context,
	codeHash string, scope string, expiresAt time.Time, maxUses int,
	createdBy string, operator string, afterState []byte) (InstallCredential, error) {

	var credential InstallCredential
	txErr := store.withTx(ctx, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx,
			`INSERT INTO install_credentials (code_hash, scope, expires_at, max_uses, created_by)
			 VALUES ($1, $2, $3, $4, $5)
			 RETURNING id, left(code_hash, 8), scope, expires_at, max_uses, uses_count, enabled, created_by, created_at, updated_at`,
			codeHash, scope, expiresAt, maxUses, createdBy).
			Scan(&credential.ID, &credential.CodeHint, &credential.Scope, &credential.ExpiresAt,
				&credential.MaxUses, &credential.UsesCount, &credential.Enabled, &credential.CreatedBy,
				&credential.CreatedAt, &credential.UpdatedAt)
		if scanErr != nil {
			return mapUniqueViolation(scanErr)
		}
		credentialID := strconv.FormatInt(credential.ID, 10)
		return appendAuditInTx(ctx, tx, AuditActionCredentialCreate, AuditTargetCredential, credentialID,
			operator, nil, afterState)
	})
	if txErr != nil {
		return InstallCredential{}, txErr
	}
	return credential, nil
}

// ListInstallCredentials 返回全部安装凭据（不含明文代码，仅 code_hint），按生成时间倒序。
func (store *Store) ListInstallCredentials(ctx context.Context) ([]InstallCredential, error) {
	rows, queryErr := store.pool.Query(ctx,
		`SELECT id, left(code_hash, 8), scope, expires_at, max_uses, uses_count, enabled, created_by, created_at, updated_at
		   FROM install_credentials ORDER BY id DESC`)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	credentialList := make([]InstallCredential, 0)
	for rows.Next() {
		var credential InstallCredential
		if scanErr := rows.Scan(&credential.ID, &credential.CodeHint, &credential.Scope, &credential.ExpiresAt,
			&credential.MaxUses, &credential.UsesCount, &credential.Enabled, &credential.CreatedBy,
			&credential.CreatedAt, &credential.UpdatedAt); scanErr != nil {
			return nil, scanErr
		}
		credentialList = append(credentialList, credential)
	}
	return credentialList, rows.Err()
}

// RevokeInstallCredentialWithAudit 吊销（停用）安装凭据并同事务落 credential_revoke 审计；
// 不存在或已停用返回 ErrNotFound（幂等吊销不重复留痕）。
func (store *Store) RevokeInstallCredentialWithAudit(ctx context.Context, credentialID int64, operator string) error {
	return store.withTx(ctx, func(tx pgx.Tx) error {
		commandTag, execErr := tx.Exec(ctx,
			`UPDATE install_credentials SET enabled = false, updated_at = now() WHERE id = $1 AND enabled`,
			credentialID)
		if execErr != nil {
			return execErr
		}
		if commandTag.RowsAffected() == 0 {
			return ErrNotFound
		}
		id := strconv.FormatInt(credentialID, 10)
		return appendAuditInTx(ctx, tx, AuditActionCredentialRevoke, AuditTargetCredential, id,
			operator, nil, []byte(`{"enabled":false}`))
	})
}

// ConsumeInstallCredential 原子消费安装凭据并同事务落一条使用记录：仅当代码存在、
// 启用、未过期且用量未超限时递增计数并返回 outcome=success；否则按缺省原因分类为
// rejected_*（undefined 也保留使用记录，供排查无效代码扫描）。
// 内核是 UPDATE ... WHERE 行锁：并发消费同代码被 PostgreSQL 串行化，输家在 UPDATE
// 重判 WHERE 后落入用量用尽分类，不会双花计数。
//
// 返回 (useID, outcome)。rate_limited 不走本方法：调用方限流判定后直接
// RecordCredentialUse(0, rate_limited, ...) 落记录。
func (store *Store) ConsumeInstallCredential(ctx context.Context, codeHash string, clientIP string) (int64, string, error) {
	var useID int64
	outcome := ""
	txErr := store.withTx(ctx, func(tx pgx.Tx) error {
		var credentialID int64
		consumeScanErr := tx.QueryRow(ctx,
			`UPDATE install_credentials SET uses_count = uses_count + 1, updated_at = now()
			  WHERE code_hash = $1 AND enabled AND expires_at > now() AND uses_count < max_uses
			  RETURNING id`,
			codeHash).Scan(&credentialID)
		if consumeScanErr == nil {
			outcome = CredentialOutcomeSuccess
			return recordCredentialUseInTx(ctx, tx, credentialID, outcome, "", clientIP, &useID)
		}
		if !errors.Is(consumeScanErr, pgx.ErrNoRows) {
			return consumeScanErr
		}

		// 未命中更新条件：回查代码以给出精确拒绝原因。
		var existsID int64
		var enabled bool
		var expiresAt time.Time
		lookupErr := tx.QueryRow(ctx,
			`SELECT id, enabled, expires_at FROM install_credentials WHERE code_hash = $1`, codeHash).
			Scan(&existsID, &enabled, &expiresAt)
		if errors.Is(lookupErr, pgx.ErrNoRows) {
			// 未知代码也留痕（credential_id 为空），供无效代码扫描排查。
			outcome = CredentialOutcomeRejectedInvalid
			return recordCredentialUseInTx(ctx, tx, 0, outcome, "", clientIP, &useID)
		}
		if lookupErr != nil {
			return lookupErr
		}
		outcome = rejectOutcomeFor(enabled, expiresAt)
		return recordCredentialUseInTx(ctx, tx, existsID, outcome, "", clientIP, &useID)
	})
	if txErr != nil {
		return 0, "", txErr
	}
	return useID, outcome, nil
}

// rejectOutcomeFor 依据凭据状态给出拒绝分类：停用 > 过期 > 用量用尽。
func rejectOutcomeFor(enabled bool, expiresAt time.Time) string {
	if !enabled {
		return CredentialOutcomeRejectedDisabled
	}
	if !expiresAt.After(time.Now()) {
		return CredentialOutcomeRejectedExpired
	}
	return CredentialOutcomeRejectedUsed
}

// recordCredentialUseInTx 在既有事务内落一条凭据使用记录并回填 useID。
func recordCredentialUseInTx(ctx context.Context, tx pgx.Tx,
	credentialID int64, outcome string, deviceID string, clientIP string, useID *int64) error {

	var nullableID any
	if credentialID != 0 {
		nullableID = credentialID
	}
	return tx.QueryRow(ctx,
		`INSERT INTO install_credential_uses (credential_id, outcome, device_id, client_ip)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		nullableID, outcome, deviceID, clientIP).Scan(useID)
}

// RecordCredentialUse 独立落一条凭据使用记录（限流事件用；凭证成功/拒绝走 Consume 同事务）。
func (store *Store) RecordCredentialUse(ctx context.Context, credentialID int64, outcome string, deviceID string, clientIP string) (int64, error) {
	var useID int64
	var nullableID any
	if credentialID != 0 {
		nullableID = credentialID
	}
	scanErr := store.pool.QueryRow(ctx,
		`INSERT INTO install_credential_uses (credential_id, outcome, device_id, client_ip)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		nullableID, outcome, deviceID, clientIP).Scan(&useID)
	return useID, scanErr
}

// SetCredentialUseDeviceID 注册成功后回填凭据使用记录关联的设备 ID（消费时尚未生成设备）。
func (store *Store) SetCredentialUseDeviceID(ctx context.Context, useID int64, deviceID string) error {
	_, execErr := store.pool.Exec(ctx,
		`UPDATE install_credential_uses SET device_id = $2 WHERE id = $1`, useID, deviceID)
	return execErr
}

// ListCredentialUses 某凭据的使用记录（分页，created_at 倒序）。
// credentialID 为 0 时列出无凭据归属（credential_id IS NULL）的记录——未知代码
// 被拒也会留痕，控制台据此排查无效代码扫描。
func (store *Store) ListCredentialUses(ctx context.Context, credentialID int64, page int, pageSize int) ([]CredentialUse, int, error) {
	normalizedPage, normalizedPageSize := normalizePage(page, pageSize)
	limit, offset := pageWindow(normalizedPage, normalizedPageSize)

	whereClause, listTail := "credential_id = $1", "ORDER BY id DESC LIMIT $2 OFFSET $3"
	listArgs := []any{credentialID, limit, offset}
	if credentialID == 0 {
		whereClause, listTail = "credential_id IS NULL", "ORDER BY id DESC LIMIT $1 OFFSET $2"
		listArgs = []any{limit, offset}
	}

	var totalCount int
	countErr := store.pool.QueryRow(ctx,
		"SELECT count(*) FROM install_credential_uses WHERE "+whereClause,
		listArgs[:len(listArgs)-2]...).Scan(&totalCount)
	if countErr != nil {
		return nil, 0, countErr
	}

	rows, queryErr := store.pool.Query(ctx,
		"SELECT id, credential_id, outcome, device_id, client_ip, created_at"+
			"  FROM install_credential_uses WHERE "+whereClause+
			" "+listTail,
		listArgs...)
	if queryErr != nil {
		return nil, 0, queryErr
	}
	defer rows.Close()

	useList := make([]CredentialUse, 0)
	for rows.Next() {
		var useRow CredentialUse
		if scanErr := rows.Scan(&useRow.ID, &useRow.CredentialID, &useRow.Outcome,
			&useRow.DeviceID, &useRow.ClientIP, &useRow.CreatedAt); scanErr != nil {
			return nil, 0, scanErr
		}
		useList = append(useList, useRow)
	}
	return useList, totalCount, rows.Err()
}