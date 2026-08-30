package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Device 对应 devices 表一行。
type Device struct {
	ID                 string
	DeviceID           string
	TokenHash          string
	MachineFingerprint string
	Hostname           string
	OS                 string
	Arch               string
	AgentVersion       string
	Plugins            []byte
	Status             string
	FirstSeenAt        time.Time
	LastSeenAt         time.Time
}

const deviceColumns = `id, device_id, token_hash, machine_fingerprint, hostname, os, arch, agent_version, plugins, status, first_seen_at, last_seen_at`

// 注册凭证哨兵错误：轮换 Token 必须证明持有既有凭证，杜绝仅凭指纹顶替他人设备。
var (
	// ErrCredentialRequired 命中既有指纹但未携带凭证（或并发插入冲突），
	// 调用方应携带既有 Token 重试，或先由管理员吊销后再注册。
	ErrCredentialRequired = errors.New("credential required")
	// ErrCredentialMismatch 携带的凭证与设备既有 Token 不符。
	ErrCredentialMismatch = errors.New("credential mismatch")
)

// CreateDevice 写入一台新设备；id/status/时间戳由数据库生成后回填。
// 空指纹归一为 'legacy-'||device_id：active 行指纹必须唯一（部分唯一索引），
// 与 0007 迁移对历史空指纹行的兜底语义保持一致。
func (store *Store) CreateDevice(ctx context.Context, device *Device) error {
	if len(device.Plugins) == 0 {
		device.Plugins = []byte(`[]`)
	}
	normalizeFingerprint(device)
	return store.pool.QueryRow(ctx,
		`INSERT INTO devices (device_id, token_hash, machine_fingerprint, hostname, os, arch, agent_version, plugins)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, status, first_seen_at, last_seen_at`,
		device.DeviceID, device.TokenHash, device.MachineFingerprint, device.Hostname, device.OS,
		device.Arch, device.AgentVersion, device.Plugins,
	).Scan(&device.ID, &device.Status, &device.FirstSeenAt, &device.LastSeenAt)
}

// FindDeviceIDByFingerprint 按机器指纹反查设备 ID；未注册过返回 ErrNotFound。

// RegisterDeviceAtomic 原子完成「注册或凭证证明轮换」，单事务内对指纹行取锁，
// 杜绝原先「查-改」两步间的并发竞态与无凭证顶替：
//   - 指纹行不存在 → 插入新设备（active；status/时间戳回填 device）；
//   - active 指纹行存在 → 必须携带旧 Token 作凭证：无凭证 ErrCredentialRequired、
//     凭证不符 ErrCredentialMismatch；匹配则原地轮换 token_hash 并刷新心跳，
//     设备身份不变（防顶替）；
//   - 仅 revoked 历史行存在（指纹已释放）→ 直接新建 active 行，无需旧凭证——管理员
//     吊销后令牌丢失的恢复路径；吊销旧行保留作为审计留痕（部分唯一索引下同指纹可
//     并存 active/revoked）。
//
// 返回 (deviceID, created, error)：created=true 为新注册；配合 partial unique 索引，
// 并发插入同指纹 active 行时由 23505 兜底并归一为 ErrCredentialRequired。
func (store *Store) RegisterDeviceAtomic(ctx context.Context,
	device *Device, claimedTokenHash string) (string, bool, error) {

	tx, beginErr := store.pool.Begin(ctx)
	if beginErr != nil {
		return "", false, beginErr
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 同一指纹可能并存 revoked 历史行与 active 行：优先取出 active，否则取最早登记行。
	var existingDeviceID, storedTokenHash, deviceStatus string
	scanErr := tx.QueryRow(ctx,
		`SELECT device_id, token_hash, status FROM devices
		  WHERE machine_fingerprint = $1
		  ORDER BY (status = 'active') DESC, first_seen_at ASC LIMIT 1
		  FOR UPDATE`,
		device.MachineFingerprint,
	).Scan(&existingDeviceID, &storedTokenHash, &deviceStatus)

	switch {
	case errors.Is(scanErr, pgx.ErrNoRows):
		device.Status = "active"
		if insertErr := insertDeviceInTx(ctx, tx, device); insertErr != nil {
			return "", false, mapFingerprintConflict(insertErr)
		}
		return device.DeviceID, true, tx.Commit(ctx)

	case scanErr != nil:
		return "", false, scanErr
	}

	if deviceStatus == "active" {
		// active 行存在：必须凭旧 Token 证明归属，防顶替注册轮换。
		if claimedTokenHash == "" {
			return "", false, ErrCredentialRequired
		}
		if subtle.ConstantTimeCompare([]byte(claimedTokenHash), []byte(storedTokenHash)) != 1 {
			return "", false, ErrCredentialMismatch
		}
		// 凭证匹配：原地轮换，设备身份不变。
		if _, updateErr := tx.Exec(ctx,
			`UPDATE devices SET token_hash = $2, last_seen_at = now() WHERE device_id = $1`,
			existingDeviceID, device.TokenHash); updateErr != nil {
			return "", false, updateErr
		}
		return existingDeviceID, false, tx.Commit(ctx)
	}

	// 仅剩 revoked 历史行：指纹已释放，直接注册新 active 行（管理员吊销后令牌
	// 丢失的恢复路径，无需旧凭证）；吊销旧行保留审计留痕，部分唯一索引允许
	// active/revoked 同指纹并存。
	device.Status = "active"
	if insertErr := insertDeviceInTx(ctx, tx, device); insertErr != nil {
		return "", false, mapFingerprintConflict(insertErr)
	}
	return device.DeviceID, true, tx.Commit(ctx)
}

// insertDeviceInTx 在给定事务内插入设备并回填 id/status/时间戳。
func insertDeviceInTx(ctx context.Context, tx pgx.Tx, device *Device) error {
	if len(device.Plugins) == 0 {
		device.Plugins = []byte(`[]`)
	}
	normalizeFingerprint(device)
	return tx.QueryRow(ctx,
		`INSERT INTO devices (device_id, token_hash, machine_fingerprint, hostname, os, arch, agent_version, plugins, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, status, first_seen_at, last_seen_at`,
		device.DeviceID, device.TokenHash, device.MachineFingerprint, device.Hostname, device.OS,
		device.Arch, device.AgentVersion, device.Plugins, device.Status,
	).Scan(&device.ID, &device.Status, &device.FirstSeenAt, &device.LastSeenAt)
}

// normalizeFingerprint 空指纹归一（legacy- + device_id），唯一约束下换新非注册路径。
func normalizeFingerprint(device *Device) {
	if device.MachineFingerprint == "" {
		device.MachineFingerprint = "legacy-" + device.DeviceID
	}
}

// mapFingerprintConflict 把并发插入同指纹 active 行触发的 23505 归一为凭证错误：
// 竞态输家应携带既有凭证重试（请求方当前无凭证即申领新令牌失败，交给上层 409）。
func mapFingerprintConflict(insertErr error) error {
	var pgError *pgconn.PgError
	if errors.As(insertErr, &pgError) && pgError.Code == "23505" {
		return ErrCredentialRequired
	}
	return insertErr
}
func (store *Store) FindDeviceIDByFingerprint(ctx context.Context, machineFingerprint string) (string, error) {
	var deviceID string
	scanErr := store.pool.QueryRow(ctx,
		`SELECT device_id FROM devices WHERE machine_fingerprint = $1`, machineFingerprint).Scan(&deviceID)
	if errors.Is(scanErr, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if scanErr != nil {
		return "", scanErr
	}
	return deviceID, nil
}

// UpdateDeviceTokenHash 轮换设备 Token（重复注册场景）：换哈希并顺带刷新心跳。
func (store *Store) UpdateDeviceTokenHash(ctx context.Context, deviceID string, tokenHash string) error {
	commandTag, err := store.pool.Exec(ctx,
		`UPDATE devices SET token_hash = $2, last_seen_at = now() WHERE device_id = $1`, deviceID, tokenHash)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetDeviceByTokenHash 按 Token 哈希查设备（终端鉴权路径），未命中返回 ErrNotFound。
func (store *Store) GetDeviceByTokenHash(ctx context.Context, tokenHash string) (*Device, error) {
	var device Device
	scanErr := store.pool.QueryRow(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE token_hash = $1`, tokenHash,
	).Scan(&device.ID, &device.DeviceID, &device.TokenHash, &device.MachineFingerprint,
		&device.Hostname, &device.OS, &device.Arch, &device.AgentVersion, &device.Plugins,
		&device.Status, &device.FirstSeenAt, &device.LastSeenAt)
	if errors.Is(scanErr, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if scanErr != nil {
		return nil, scanErr
	}
	return &device, nil
}

// TouchDevice 刷新设备心跳时间并更新版本/插件信息。
func (store *Store) TouchDevice(ctx context.Context, deviceID string, agentVersion string, pluginsJSON []byte) error {
	if len(pluginsJSON) == 0 {
		pluginsJSON = []byte(`[]`)
	}
	commandTag, err := store.pool.Exec(ctx,
		`UPDATE devices SET last_seen_at = now(), agent_version = $2, plugins = $3 WHERE device_id = $1`,
		deviceID, agentVersion, pluginsJSON)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDeviceStatus 更新设备状态（active/revoked）；设备不存在返回 ErrNotFound。
// 吊销后设备 Token 立即失效（鉴权中间件校验 status），历史审计数据原样保留。
func (store *Store) SetDeviceStatus(ctx context.Context, deviceID string, status string) error {
	commandTag, err := store.pool.Exec(ctx,
		`UPDATE devices SET status = $2 WHERE device_id = $1`, deviceID, status)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListDevices 返回全部设备，按最后心跳倒序（在线判定由上层依据 last_seen_at 计算）。
func (store *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT `+deviceColumns+` FROM devices ORDER BY last_seen_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]Device, 0)
	for rows.Next() {
		var device Device
		if scanErr := rows.Scan(&device.ID, &device.DeviceID, &device.TokenHash, &device.MachineFingerprint,
			&device.Hostname, &device.OS, &device.Arch, &device.AgentVersion, &device.Plugins,
			&device.Status, &device.FirstSeenAt, &device.LastSeenAt); scanErr != nil {
			return nil, scanErr
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}
