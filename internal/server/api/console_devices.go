package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/store"
)

// jsonUnmarshalStrict 宽松反序列化辅助：仅用于把已校验的库内 JSON 展示为 any。
func jsonUnmarshalStrict(rawJSON []byte, target any) error {
	if len(rawJSON) == 0 {
		return nil
	}
	return json.Unmarshal(rawJSON, target)
}

// DeviceHealth 设备健康态（最后心跳时间 × 终端带外积压联合判定）。
type DeviceHealth string

const (
	DeviceHealthOnline   DeviceHealth = "online"
	DeviceHealthAbnormal DeviceHealth = "abnormal"
	DeviceHealthOffline  DeviceHealth = "offline"
)

// deviceHealth 计算设备健康态：
//   - offline：最后心跳距今超过在线窗口（onlineWindow 秒）——连接已断；
//   - abnormal：在线但最近心跳上报存在带外积压（断网缓存未送达服务端）——数据滞留；
//   - online：在线且无积压。
func deviceHealth(lastSeenAt time.Time, spoolPendingBatches int64, now time.Time) DeviceHealth {
	if now.Sub(lastSeenAt) >= onlineWindow*time.Second {
		return DeviceHealthOffline
	}
	if spoolPendingBatches > 0 {
		return DeviceHealthAbnormal
	}
	return DeviceHealthOnline
}

// HandleListDevices GET /devices —— 设备列表 + 健康态判定。
func (api *Router) HandleListDevices(routerCtx *gin.Context) {
	deviceList, listErr := api.eventStore.ListDevices(routerCtx.Request.Context())
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询设备失败"})
		return
	}

	items := make([]gin.H, 0, len(deviceList))
	nowTime := time.Now()
	for _, deviceRow := range deviceList {
		var plugins any
		_ = jsonUnmarshalStrict(deviceRow.Plugins, &plugins)
		health := deviceHealth(deviceRow.LastSeenAt, deviceRow.SpoolPendingBatches, nowTime)
		items = append(items, gin.H{
			"device_id":     deviceRow.DeviceID,
			"hostname":      deviceRow.Hostname,
			"os":            deviceRow.OS,
			"arch":          deviceRow.Arch,
			"agent_version": deviceRow.AgentVersion,
			"plugins":       plugins,
			"status":        deviceRow.Status,
			// online 保留历史语义（在线窗口内即 true）；health 承载三态细节
			"online":   health != DeviceHealthOffline,
			"health":   health,
			"spool_pending_batches": deviceRow.SpoolPendingBatches,
			"spool_pending_bytes":   deviceRow.SpoolPendingBytes,
			"first_seen_at": deviceRow.FirstSeenAt,
			"last_seen_at":  deviceRow.LastSeenAt,
		})
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items})
}

// HandlePatchDeviceStatus PATCH /devices/:deviceID —— 吊销/恢复设备。
// body 仅接受 {"status":"revoked"|"active"}；吊销即时生效（Token 鉴权中断），
// 历史审计数据原样保留；每次变更同事务落 device_revoke/device_restore 审计；
// ErrNotFound → 404。
func (api *Router) HandlePatchDeviceStatus(routerCtx *gin.Context) {
	var statusRequest struct {
		Status string `json:"status"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&statusRequest); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}
	if statusRequest.Status != "revoked" && statusRequest.Status != "active" {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "status 仅支持 revoked / active"})
		return
	}

	statusErr := api.eventStore.SetDeviceStatusWithAudit(routerCtx.Request.Context(),
		routerCtx.Param("deviceID"), statusRequest.Status, auditOperator(routerCtx))
	switch {
	case statusErr == nil:
		routerCtx.JSON(http.StatusOK, gin.H{"device_id": routerCtx.Param("deviceID"), "status": statusRequest.Status})
	case errors.Is(statusErr, store.ErrNotFound):
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "设备不存在"})
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "更新设备状态失败"})
	}
}
