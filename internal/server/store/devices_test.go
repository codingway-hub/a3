package store

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateDeviceAndGetByTokenHash(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "devices")
	deviceStore := NewStore(testPool)
	ctx := context.Background()

	newDevice := &Device{
		DeviceID:     "dev-test-001",
		TokenHash:    "hash-of-token-001",
		Hostname:     "liu-macbook",
		OS:           "darwin",
		Arch:         "amd64",
		AgentVersion: "v1.0.0",
		Plugins:      []byte(`["claude@v1.0.0"]`),
	}
	createErr := deviceStore.CreateDevice(ctx, newDevice)
	require.NoError(t, createErr)

	assert.NotEmpty(t, newDevice.ID, "数据库应回填 uuid 主键")
	assert.Equal(t, "active", newDevice.Status)
	assert.WithinDuration(t, time.Now(), newDevice.FirstSeenAt, 10*time.Second)

	fetched, fetchErr := deviceStore.GetDeviceByTokenHash(ctx, "hash-of-token-001")
	require.NoError(t, fetchErr)
	assert.Equal(t, newDevice.ID, fetched.ID)
	assert.Equal(t, "dev-test-001", fetched.DeviceID)
	var plugins []string
	require.NoError(t, json.Unmarshal(fetched.Plugins, &plugins))
	assert.Equal(t, []string{"claude@v1.0.0"}, plugins)

	_, missErr := deviceStore.GetDeviceByTokenHash(ctx, "hash-not-exists")
	assert.ErrorIs(t, missErr, ErrNotFound)
}

func TestTouchDeviceRefreshesHeartbeat(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "devices")
	deviceStore := NewStore(testPool)
	ctx := context.Background()

	newDevice := &Device{DeviceID: "dev-touch-001", TokenHash: "hash-touch-001", Hostname: "host-a"}
	require.NoError(t, deviceStore.CreateDevice(ctx, newDevice))
	originalLastSeen := newDevice.LastSeenAt

	time.Sleep(20 * time.Millisecond) // 保证心跳时间戳可观测地推进
	require.NoError(t, deviceStore.TouchDevice(ctx, "dev-touch-001", "v1.0.1", []byte(`["claude@v1.0.1"]`)))

	touched, fetchErr := deviceStore.GetDeviceByTokenHash(ctx, "hash-touch-001")
	require.NoError(t, fetchErr)
	assert.Equal(t, "v1.0.1", touched.AgentVersion)
	assert.True(t, touched.LastSeenAt.After(originalLastSeen), "心跳后 last_seen_at 应前进")

	touchErr := deviceStore.TouchDevice(ctx, "dev-unknown", "v1.0.1", nil)
	assert.ErrorIs(t, touchErr, ErrNotFound)
}

func TestTouchDeviceHeartbeatRefreshesSeenAndSpoolBacklog(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "devices")
	deviceStore := NewStore(testPool)
	ctx := context.Background()

	newDevice := &Device{DeviceID: "dev-heartbeat-001", TokenHash: "hash-heartbeat-001", Hostname: "host-hb"}
	require.NoError(t, deviceStore.CreateDevice(ctx, newDevice))
	originalLastSeen := newDevice.LastSeenAt

	time.Sleep(20 * time.Millisecond) // 保证时间戳可观测地推进
	require.NoError(t, deviceStore.TouchDeviceHeartbeat(ctx, "dev-heartbeat-001", 7, 4096))

	beaten, fetchErr := deviceStore.GetDeviceByTokenHash(ctx, "hash-heartbeat-001")
	require.NoError(t, fetchErr)
	assert.True(t, beaten.LastSeenAt.After(originalLastSeen), "心跳后 last_seen_at 应前进")
	assert.Equal(t, int64(7), beaten.SpoolPendingBatches, "积压批次数应落库")
	assert.Equal(t, int64(4096), beaten.SpoolPendingBytes, "积压字节数应落库")

	// 未知设备心跳返回 ErrNotFound
	assert.ErrorIs(t, deviceStore.TouchDeviceHeartbeat(ctx, "dev-unknown", 0, 0), ErrNotFound)
}

func TestListDevicesOrdersByLastSeenDesc(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "devices")
	deviceStore := NewStore(testPool)
	ctx := context.Background()

	firstDevice := &Device{DeviceID: "dev-list-first", TokenHash: "hash-list-first", Hostname: "host-1"}
	require.NoError(t, deviceStore.CreateDevice(ctx, firstDevice))
	time.Sleep(20 * time.Millisecond)
	secondDevice := &Device{DeviceID: "dev-list-second", TokenHash: "hash-list-second", Hostname: "host-2"}
	require.NoError(t, deviceStore.CreateDevice(ctx, secondDevice))

	devices, listErr := deviceStore.ListDevices(ctx)
	require.NoError(t, listErr)
	require.Len(t, devices, 2)
	assert.Equal(t, "dev-list-second", devices[0].DeviceID, "最近心跳的设备排最前")
}

func TestRegisterDeviceAtomicReuseWithoutRotation(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "devices", "audit_log")
	deviceStore := NewStore(testPool)
	ctx := context.Background()

	originalHash := "hash-original-001"
	seeded := &Device{
		DeviceID: "dev-reuse-001", TokenHash: originalHash, Hostname: "macbook",
		MachineFingerprint: "fp-reuse-001",
	}
	require.NoError(t, deviceStore.CreateDevice(ctx, seeded))

	// 携带正确凭证复用身份：返回 created=false、Token 哈希不变
	candidate := &Device{
		DeviceID: "dev-ignored", TokenHash: "hash-should-not-write", Hostname: "macbook",
		MachineFingerprint: "fp-reuse-001",
	}
	reusedID, created, reuseErr := deviceStore.RegisterDeviceAtomic(ctx, candidate, originalHash)
	require.NoError(t, reuseErr)
	assert.False(t, created, "凭据匹配应复用既有身份，而非新建")
	assert.Equal(t, "dev-reuse-001", reusedID, "返回既有设备 ID")

	fetched, fetchErr := deviceStore.GetDeviceByTokenHash(ctx, originalHash)
	require.NoError(t, fetchErr, "原 Token 必须仍有效")
	assert.Equal(t, "hash-original-001", fetched.TokenHash, "重复注册不得轮换 Token")
	_, shouldMissErr := deviceStore.GetDeviceByTokenHash(ctx, "hash-should-not-write")
	assert.ErrorIs(t, shouldMissErr, ErrNotFound, "未写入的候选哈希不应存在")
}

func TestRegisterDeviceAtomicConcurrentCreatesOneDevice(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "devices")
	deviceStore := NewStore(testPool)
	ctx := context.Background()

	const competitors = 12
	createdCount := 0
	var mu sync.Mutex
	var waitGroup sync.WaitGroup

	for i := 0; i < competitors; i++ {
		waitGroup.Add(1)
		go func(workerIndex int) {
			defer waitGroup.Done()
			candidate := &Device{
				DeviceID: "dev-concurrent-" + strconv.Itoa(workerIndex),
				TokenHash: "hash-concurrent-" + strconv.Itoa(workerIndex),
				Hostname: "host", MachineFingerprint: "fp-concurrent-001",
			}
			_, created, registerErr := deviceStore.RegisterDeviceAtomic(ctx, candidate, "")
			if registerErr != nil {
				assert.ErrorIs(t, registerErr, ErrCredentialRequired, "并发冲突应归一为凭证需求")
				return
			}
			if !created {
				return
			}
			mu.Lock()
			createdCount++
			mu.Unlock()
		}(i)
	}
	waitGroup.Wait()
	assert.Equal(t, 1, createdCount, "同指纹并发注册只允许一台设备胜出")

	devices, listErr := deviceStore.ListDevices(ctx)
	require.NoError(t, listErr)
	require.Len(t, devices, 1, "同指纹只留一个 active 行")
	assert.Equal(t, "fp-concurrent-001", devices[0].MachineFingerprint)
}

func TestRotateDeviceTokenWithAudit(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "devices", "audit_log")
	deviceStore := NewStore(testPool)
	ctx := context.Background()

	seeded := &Device{DeviceID: "dev-rotate-001", TokenHash: "hash-old-001", Hostname: "macbook"}
	require.NoError(t, deviceStore.CreateDevice(ctx, seeded))

	require.NoError(t, deviceStore.RotateDeviceTokenWithAudit(ctx, "dev-rotate-001", "hash-new-001", "admin-oper"))

	fetched, fetchErr := deviceStore.GetDeviceByTokenHash(ctx, "hash-new-001")
	require.NoError(t, fetchErr)
	assert.Equal(t, "dev-rotate-001", fetched.DeviceID, "管理员批准轮换后新 Token 生效")
	_, oldErr := deviceStore.GetDeviceByTokenHash(ctx, "hash-old-001")
	assert.ErrorIs(t, oldErr, ErrNotFound, "旧 Token 立即失效")

	// 审计留痕 device_token_rotate（约束已扩 action 集合）
	entries, total, auditErr := deviceStore.ListAuditLog(ctx, AuditFilter{TargetType: "device", TargetID: "dev-rotate-001"})
	require.NoError(t, auditErr)
	assert.Equal(t, 1, total)
	require.Len(t, entries, 1)
	assert.Equal(t, AuditActionDeviceTokenRotate, entries[0].Action)
	assert.Equal(t, "admin-oper", entries[0].Operator)

	// 已吊销设备禁止轮换
	require.NoError(t, deviceStore.SetDeviceStatus(ctx, "dev-rotate-001", "revoked"))
	rotateErr := deviceStore.RotateDeviceTokenWithAudit(ctx, "dev-rotate-001", "hash-x", "admin-oper")
	assert.ErrorIs(t, rotateErr, ErrNotFound, "已吊销设备换发应拒绝（走吊销后重注册）")
}
