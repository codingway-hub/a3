package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// jsonUnmarshalStrict 宽松反序列化辅助：仅用于把已校验的库内 JSON 展示为 any。
func jsonUnmarshalStrict(rawJSON []byte, target any) error {
	if len(rawJSON) == 0 {
		return nil
	}
	return json.Unmarshal(rawJSON, target)
}

// HandleListDevices GET /devices —— 设备列表 + 在线判定。
func (api *Router) HandleListDevices(routerCtx *gin.Context) {
	deviceList, listErr := api.eventStore.ListDevices(routerCtx.Request.Context())
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询设备失败"})
		return
	}

	items := make([]gin.H, 0, len(deviceList))
	for _, deviceRow := range deviceList {
		var plugins any
		_ = jsonUnmarshalStrict(deviceRow.Plugins, &plugins)
		items = append(items, gin.H{
			"device_id":     deviceRow.DeviceID,
			"hostname":      deviceRow.Hostname,
			"os":            deviceRow.OS,
			"arch":          deviceRow.Arch,
			"agent_version": deviceRow.AgentVersion,
			"plugins":       plugins,
			"status":        deviceRow.Status,
			"online":        time.Since(deviceRow.LastSeenAt) < onlineWindow*time.Second,
			"first_seen_at": deviceRow.FirstSeenAt,
			"last_seen_at":  deviceRow.LastSeenAt,
		})
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items})
}
