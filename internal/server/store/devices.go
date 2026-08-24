package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
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

// CreateDevice 写入一台新设备；id/status/时间戳由数据库生成后回填。
func (store *Store) CreateDevice(ctx context.Context, device *Device) error {
	if len(device.Plugins) == 0 {
		device.Plugins = []byte(`[]`)
	}
	return store.pool.QueryRow(ctx,
		`INSERT INTO devices (device_id, token_hash, machine_fingerprint, hostname, os, arch, agent_version, plugins)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, status, first_seen_at, last_seen_at`,
		device.DeviceID, device.TokenHash, device.MachineFingerprint, device.Hostname, device.OS,
		device.Arch, device.AgentVersion, device.Plugins,
	).Scan(&device.ID, &device.Status, &device.FirstSeenAt, &device.LastSeenAt)
}

// FindDeviceIDByFingerprint 按机器指纹反查设备 ID；未注册过返回 ErrNotFound。
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
