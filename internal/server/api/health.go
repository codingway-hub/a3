package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// HandleHealthz 存活/就绪探测：DB 可达则 200 ok，否则 503 degraded。
// 公共端点（先例 install.sh），供 compose 健康检查与采集器 doctor 探活，无需登录。
func (api *Router) HandleHealthz(routerCtx *gin.Context) {
	dbState, statusBody := "ok", "ok"
	switch {
	case api.eventStore == nil:
		// 测试可空装配（install_routes_test 以 NewRouter(nil, nil, ...) 构建）
		dbState, statusBody = "error", "degraded"
	default:
		pingCtx, cancel := context.WithTimeout(routerCtx.Request.Context(), 2*time.Second)
		defer cancel()
		if pingErr := api.eventStore.Ping(pingCtx); pingErr != nil {
			dbState, statusBody = "error", "degraded"
		}
	}
	statusCode := http.StatusOK
	if dbState == "error" {
		statusCode = http.StatusServiceUnavailable
	}
	routerCtx.JSON(statusCode, gin.H{
		"status":         statusBody,
		"version":        api.version,
		"uptime_seconds": int64(time.Since(api.startedAt).Seconds()),
		"db":             dbState,
		"time":           time.Now().Format(time.RFC3339),
	})
}