package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// HandleStatsOverview 返回概览页统计卡数据。
func (api *Router) HandleStatsOverview(routerCtx *gin.Context) {
	ctx := routerCtx.Request.Context()

	todayStart := time.Now().Truncate(24 * time.Hour)
	todayEventCount, countErr := api.eventStore.CountEventsSince(ctx, todayStart)
	if countErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "统计事件数失败"})
		return
	}

	totalSessions, riskySessions, sessionErr := api.eventStore.CountSessions(ctx)
	if sessionErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "统计会话数失败"})
		return
	}

	openAlertCount, alertErr := api.eventStore.CountOpenAlerts(ctx)
	if alertErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "统计告警数失败"})
		return
	}

	activeDeviceCount, deviceErr := api.countActiveDevices(ctx)
	if deviceErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "统计设备数失败"})
		return
	}

	routerCtx.JSON(http.StatusOK, gin.H{
		"today_event_count":   todayEventCount,
		"active_device_count": activeDeviceCount,
		"open_alert_count":    openAlertCount,
		"total_sessions":      totalSessions,
		"risky_sessions":      riskySessions,
	})
}

// countActiveDevices 统计在线窗口内的设备数（设备量级小，内存过滤足够）。
func (api *Router) countActiveDevices(ctx context.Context) (int, error) {
	deviceList, listErr := api.eventStore.ListDevices(ctx)
	if listErr != nil {
		return 0, listErr
	}
	activeCount := 0
	for _, deviceRow := range deviceList {
		if time.Since(deviceRow.LastSeenAt) < onlineWindow*time.Second {
			activeCount++
		}
	}
	return activeCount, nil
}
