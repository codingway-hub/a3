package store

import (
	"context"
	"encoding/json"
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
