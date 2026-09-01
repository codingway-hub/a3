package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/servetest"
)

// TestDeviceHealthClassification 纯函数三态判定：离线(超窗口) > 异常(有积压) > 在线。
func TestDeviceHealthClassification(t *testing.T) {
	now := time.Now()
	withinWindow := now.Add(-2 * time.Minute) // 在线窗口（5 分钟）内
	boundaryAgo := now.Add(-onlineWindow * time.Second)

	t.Run("在线且无积压 → online", func(t *testing.T) {
		assert.Equal(t, DeviceHealthOnline, deviceHealth(withinWindow, 0, now))
	})
	t.Run("在线但有积压 → abnormal", func(t *testing.T) {
		assert.Equal(t, DeviceHealthAbnormal, deviceHealth(withinWindow, 3, now))
	})
	t.Run("恰在窗口边界 → offline", func(t *testing.T) {
		assert.Equal(t, DeviceHealthOffline, deviceHealth(boundaryAgo, 0, now))
	})
	t.Run("超窗口即使有积压也判离线", func(t *testing.T) {
		longAgo := now.Add(-1 * time.Hour)
		assert.Equal(t, DeviceHealthOffline, deviceHealth(longAgo, 999, now))
	})
}

// TestListDevicesHealthAndSpoolFields 列表接口承载三态健康与积压视图：
// 严格在线/带积压(abnormal)/历史心跳(offline) 三种设备，断言 health 与 spool 字段落位。
func TestListDevicesHealthAndSpoolFields(t *testing.T) {
	test := newFixture(t)
	ctx := context.Background()
	test.login(t)

	// ① 种两台设备：一台心跳带积压，一台仅注册（last_seen 为注册时刻）
	servetest.MustSeedDevice(t, test.eventStore, "dev-hb-abnormal")
	require.NoError(t, test.eventStore.TouchDeviceHeartbeat(ctx, "dev-hb-abnormal", 3, 8192))
	servetest.MustSeedDevice(t, test.eventStore, "dev-hb-online")

	devices := test.do(http.MethodGet, "/api/v1/devices", "", test.jwtToken)
	require.Equal(t, http.StatusOK, devices.Code)
	var listResponse struct {
		Items []struct {
			DeviceID           string          `json:"device_id"`
			Online             bool            `json:"online"`
			Health             DeviceHealth    `json:"health"`
			SpoolPendingBatches int64          `json:"spool_pending_batches"`
			SpoolPendingBytes  int64          `json:"spool_pending_bytes"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(devices.Body.Bytes(), &listResponse))
	require.Len(t, listResponse.Items, 2)

	healthByDevice := make(map[string]DeviceHealth, 2)
	spoolByDevice := make(map[string][2]int64, 2)
	onlineByDevice := make(map[string]bool, 2)
	for _, deviceItem := range listResponse.Items {
		healthByDevice[deviceItem.DeviceID] = deviceItem.Health
		spoolByDevice[deviceItem.DeviceID] = [2]int64{deviceItem.SpoolPendingBatches, deviceItem.SpoolPendingBytes}
		onlineByDevice[deviceItem.DeviceID] = deviceItem.Online
	}

	assert.Equal(t, DeviceHealthAbnormal, healthByDevice["dev-hb-abnormal"], "在线但带积压 → 数据滞留")
	assert.Equal(t, int64(3), spoolByDevice["dev-hb-abnormal"][0])
	assert.Equal(t, int64(8192), spoolByDevice["dev-hb-abnormal"][1])
	assert.True(t, onlineByDevice["dev-hb-abnormal"], "abnormal 仍在线，online 布尔应保持真")

	assert.Equal(t, DeviceHealthOnline, healthByDevice["dev-hb-online"], "注册即心跳，无积压 → 在线")
	assert.Equal(t, int64(0), spoolByDevice["dev-hb-online"][0], "未上报过积压应默认 0")
	assert.True(t, onlineByDevice["dev-hb-online"])

	// ③ 把一台设备心跳拨回在线窗口之前 → offline，online 布尔翻为假
	backdatedPool, poolErr := pgxpool.New(context.Background(), servetest.TestDatabaseURL(t))
	require.NoError(t, poolErr)
	defer backdatedPool.Close()
	_, updateErr := backdatedPool.Exec(ctx,
		`UPDATE devices SET last_seen_at = now() - interval '10 minutes' WHERE device_id = $1`, "dev-hb-online")
	require.NoError(t, updateErr)

	staleDevices := test.do(http.MethodGet, "/api/v1/devices", "", test.jwtToken)
	require.Equal(t, http.StatusOK, staleDevices.Code)
	var staleResponse struct {
		Items []struct {
			DeviceID string       `json:"device_id"`
			Online   bool         `json:"online"`
			Health   DeviceHealth `json:"health"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(staleDevices.Body.Bytes(), &staleResponse))
	var staleDevice struct {
		Online bool         `json:"online"`
		Health DeviceHealth `json:"health"`
	}
	for _, deviceItem := range staleResponse.Items {
		if deviceItem.DeviceID == "dev-hb-online" {
			staleDevice.Online = deviceItem.Online
			staleDevice.Health = deviceItem.Health
		}
	}
	assert.Equal(t, DeviceHealthOffline, staleDevice.Health)
	assert.False(t, staleDevice.Online, "离线设备的 online 布尔必须翻假，保持历史语义")
}