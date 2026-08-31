package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// 控制台用户（RBAC）：admin 全权；auditor 只读 + 确认告警。
// 口令仅存 bcrypt 哈希；查询列表不回哈希列。

// AdminUser 对应 admin_users 表一行。
type AdminUser struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string // admin|auditor（迁移 CHECK 约束兜底）
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// adminUserColumns 列表查询用（不含口令哈希，杜绝意外外泄）；单行认证查询单独拼列。
const adminUserColumns = `id, username, role, enabled, created_at, updated_at`

const adminUserFullColumns = `id, username, password_hash, role, enabled, created_at, updated_at`

// CountAdminUsers 返回账号总数；为 0 时服务端启动用 env 凭据种子首个 admin。
func (store *Store) CountAdminUsers(ctx context.Context) (int, error) {
	var userCount int
	scanErr := store.pool.QueryRow(ctx, `SELECT count(*) FROM admin_users`).Scan(&userCount)
	return userCount, scanErr
}

// CreateAdminUser 新建账号；同名冲突返回 ErrAlreadyExists。
func (store *Store) CreateAdminUser(ctx context.Context, username string, passwordHash string, role string) error {
	_, execErr := store.pool.Exec(ctx,
		`INSERT INTO admin_users (username, password_hash, role) VALUES ($1, $2, $3)`,
		username, passwordHash, role)
	return mapUniqueViolation(execErr)
}

// mapUserScanErr 把无行扫描错误归一为 ErrNotFound，其余原样返回。
func mapUserScanErr(scanErr error) error {
	if errors.Is(scanErr, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return scanErr
}

// GetAdminUserByUsername 按用户名取完整行（含口令哈希，仅登录校验用）；不存在返回 ErrNotFound。
func (store *Store) GetAdminUserByUsername(ctx context.Context, username string) (AdminUser, error) {
	var userRow AdminUser
	scanErr := store.pool.QueryRow(ctx,
		`SELECT `+adminUserFullColumns+` FROM admin_users WHERE username = $1`, username).
		Scan(&userRow.ID, &userRow.Username, &userRow.PasswordHash, &userRow.Role,
			&userRow.Enabled, &userRow.CreatedAt, &userRow.UpdatedAt)
	if scanErr != nil {
		return AdminUser{}, mapUserScanErr(scanErr)
	}
	return userRow, nil
}

// ListAdminUsers 返回全部账号（不含口令哈希），按创建时间升序。
func (store *Store) ListAdminUsers(ctx context.Context) ([]AdminUser, error) {
	rows, queryErr := store.pool.Query(ctx,
		`SELECT `+adminUserColumns+` FROM admin_users ORDER BY id ASC`)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	userList := make([]AdminUser, 0)
	for rows.Next() {
		var userRow AdminUser
		if scanErr := rows.Scan(&userRow.ID, &userRow.Username, &userRow.Role,
			&userRow.Enabled, &userRow.CreatedAt, &userRow.UpdatedAt); scanErr != nil {
			return nil, scanErr
		}
		userList = append(userList, userRow)
	}
	return userList, rows.Err()
}

// SetAdminUserEnabled 停用/启用账号，返回更新后行供审计快照；不存在返回 ErrNotFound。
func (store *Store) SetAdminUserEnabled(ctx context.Context, userID int64, enabled bool) (AdminUser, error) {
	return store.updateAdminUserRow(ctx,
		`UPDATE admin_users SET enabled = $2, updated_at = now() WHERE id = $1`, userID, enabled)
}

// SetAdminUserRole 变更账号角色，返回更新后行供审计快照；不存在返回 ErrNotFound。
func (store *Store) SetAdminUserRole(ctx context.Context, userID int64, role string) (AdminUser, error) {
	return store.updateAdminUserRow(ctx,
		`UPDATE admin_users SET role = $2, updated_at = now() WHERE id = $1`, userID, role)
}

// updateAdminUserRow 执行 UPDATE ... RETURNING 完整行（不含哈希也够快照；哈希不外泄）。
func (store *Store) updateAdminUserRow(ctx context.Context, updateQuery string, userID int64, updateValue any) (AdminUser, error) {
	var userRow AdminUser
	scanErr := store.pool.QueryRow(ctx, updateQuery+` RETURNING `+adminUserColumns,
		userID, updateValue).
		Scan(&userRow.ID, &userRow.Username, &userRow.Role,
			&userRow.Enabled, &userRow.CreatedAt, &userRow.UpdatedAt)
	if scanErr != nil {
		return AdminUser{}, mapUserScanErr(scanErr)
	}
	return userRow, nil
}

// SetAdminUserPassword 重置口令哈希；不存在返回 ErrNotFound。
func (store *Store) SetAdminUserPassword(ctx context.Context, userID int64, passwordHash string) error {
	commandTag, execErr := store.pool.Exec(ctx,
		`UPDATE admin_users SET password_hash = $2, updated_at = now() WHERE id = $1`,
		userID, passwordHash)
	if execErr != nil {
		return execErr
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetAdminUserByID 按 ID 取完整行（含口令哈希列，仅审计快照前取用户名用）；不存在返回 ErrNotFound。
func (store *Store) GetAdminUserByID(ctx context.Context, userID int64) (AdminUser, error) {
	var userRow AdminUser
	scanErr := store.pool.QueryRow(ctx,
		`SELECT `+adminUserFullColumns+` FROM admin_users WHERE id = $1`, userID).
		Scan(&userRow.ID, &userRow.Username, &userRow.PasswordHash, &userRow.Role,
			&userRow.Enabled, &userRow.CreatedAt, &userRow.UpdatedAt)
	if scanErr != nil {
		return AdminUser{}, mapUserScanErr(scanErr)
	}
	return userRow, nil
}

// CreateAdminUserWithAudit 建号并同事务留痕（业务生效则留痕必在）；同名冲突 ErrAlreadyExists 无留痕。
func (store *Store) CreateAdminUserWithAudit(ctx context.Context,
	username string, passwordHash string, role string, operator string, afterState []byte) error {

	return store.withTx(ctx, func(tx pgx.Tx) error {
		if insertErr := tx.QueryRow(ctx,
			`INSERT INTO admin_users (username, password_hash, role) VALUES ($1, $2, $3)
			 RETURNING id`, username, passwordHash, role).Scan(new(int64)); insertErr != nil {
			return mapUniqueViolation(insertErr)
		}
		return appendAuditInTx(ctx, tx, AuditActionUserCreate, AuditTargetUser, username, operator, nil, afterState)
	})
}

// ResetAdminUserPasswordWithAudit 重置口令并同事务留痕（after 为 {username}）；
// 不存在返回 ErrNotFound 无留痕。
func (store *Store) ResetAdminUserPasswordWithAudit(ctx context.Context,
	userID int64, passwordHash string, operator string) (AdminUser, error) {

	var updatedRow AdminUser
	withTxErr := store.withTx(ctx, func(tx pgx.Tx) error {
		commandTag, execErr := tx.Exec(ctx,
			`UPDATE admin_users SET password_hash = $2, updated_at = now() WHERE id = $1`,
			userID, passwordHash)
		if execErr != nil {
			return execErr
		}
		if commandTag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if scanErr := tx.QueryRow(ctx,
			`SELECT `+adminUserColumns+` FROM admin_users WHERE id = $1`, userID).
			Scan(&updatedRow.ID, &updatedRow.Username, &updatedRow.Role,
				&updatedRow.Enabled, &updatedRow.CreatedAt, &updatedRow.UpdatedAt); scanErr != nil {
			return scanErr
		}
		return appendAuditInTx(ctx, tx, AuditActionUserPasswordReset, AuditTargetUser, updatedRow.Username,
			operator, nil, []byte(`{"username":"`+updatedRow.Username+`"}`))
	})
	if withTxErr != nil {
		return AdminUser{}, withTxErr
	}
	return updatedRow, nil
}
