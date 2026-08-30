// Package api 装配 a3 服务端 HTTP 层：设备侧接入路由与控制台 JWT 保护路由。
package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/alert"
	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/ingest"
	"github.com/codingway-hub/a3/internal/server/store"
)

// onlineWindow 设备在线判定窗口：最后心跳距今 5 分钟内视为在线。
const onlineWindow = 5 * 60 // 秒

// Router 持有服务端依赖并负责装配 gin 引擎。
type Router struct {
	eventStore        *store.Store
	alertService      *alert.Service
	deviceAPI         *ingest.Handler // 设备侧接入（注册/上报）；nil 则不挂载
	jwtSecret         string
	adminUsername     string
	adminPasswordHash string // 启动时对 env 明文口令做一次 bcrypt 后缓存
	webDist           string // 前端静态目录；为空则不托管
}

// RouterConfig 是装配参数。
type RouterConfig struct {
	JWTSecret         string
	AdminUsername     string
	AdminPasswordHash string
	WebDist           string
	DeviceAPI         *ingest.Handler
}

// NewRouter 构建装配器。
func NewRouter(eventStore *store.Store, alertService *alert.Service, routerConfig RouterConfig) *Router {
	return &Router{
		eventStore:        eventStore,
		alertService:      alertService,
		deviceAPI:         routerConfig.DeviceAPI,
		jwtSecret:         routerConfig.JWTSecret,
		adminUsername:     routerConfig.AdminUsername,
		adminPasswordHash: routerConfig.AdminPasswordHash,
		webDist:           routerConfig.WebDist,
	}
}

// Setup 组装并返回 gin.Engine：
//
//	/api/v1/devices/register、/api/v1/events/batch —— 设备侧（Token 鉴权，见 ingest.Handler）
//	/api/v1/*                                      —— 控制台侧（login 除外均要求 JWT）
func (api *Router) Setup() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Logger(), gin.Recovery())
	engine.MaxMultipartMemory = 8 << 20

	// 设备侧接入路由（注册公开；上报内置 Token 鉴权）
	if api.deviceAPI != nil {
		api.deviceAPI.RegisterRoutes(engine)
	}

	// 控制台 API：login 公开，其余统一 JWT 保护
	consoleGroup := engine.Group("/api/v1")
	consoleGroup.POST("/auth/login", api.HandleLogin)
	protectedGroup := consoleGroup.Group("", auth.RequireJWT(api.jwtSecret))
	{
		protectedGroup.GET("/auth/me", api.HandleMe)
		protectedGroup.GET("/stats/overview", api.HandleStatsOverview)
		protectedGroup.GET("/sessions", api.HandleListSessions)
		protectedGroup.GET("/sessions/:deviceId/:sessionKey/events", api.HandleSessionEvents)
		protectedGroup.GET("/sessions/:deviceId/:sessionKey/export", api.HandleSessionExport)
		protectedGroup.GET("/alerts", api.HandleListAlerts)
		protectedGroup.PATCH("/alerts/:alertID", api.HandleAcknowledgeAlert)
		protectedGroup.GET("/alerts/export", api.HandleAlertsExport)
		protectedGroup.GET("/devices", api.HandleListDevices)
		protectedGroup.PATCH("/devices/:deviceID", api.HandlePatchDeviceStatus)
		protectedGroup.GET("/rules", api.HandleListRules)
		protectedGroup.POST("/rules", api.HandleCreateRule)
		protectedGroup.PUT("/rules/:ruleID", api.HandleUpdateRule)
		protectedGroup.DELETE("/rules/:ruleID", api.HandleDeleteRule)
		protectedGroup.PATCH("/rules/:ruleID", api.HandlePatchRule)
		protectedGroup.GET("/audit-log", api.HandleListAuditLog)
	}

	// 前端静态托管：NoRoute 时优先回退 index.html（SPA history 路由）
	if api.webDist != "" {
		engine.Static("/assets", filepath.Join(api.webDist, "assets"))
		engine.NoRoute(func(routerCtx *gin.Context) {
			requestPath := routerCtx.Request.URL.Path
			if strings.HasPrefix(requestPath, "/api/") {
				routerCtx.JSON(http.StatusNotFound, gin.H{"error": "接口不存在"})
				return
			}
			indexPath := filepath.Join(api.webDist, "index.html")
			if _, statErr := os.Stat(indexPath); statErr != nil {
				routerCtx.String(http.StatusNotFound, "前端资源未构建")
				return
			}
			routerCtx.File(indexPath)
		})
	}
	return engine
}
