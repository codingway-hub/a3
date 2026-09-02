// Package api 装配 a3 服务端 HTTP 层：设备侧接入路由与控制台 JWT 保护路由。
package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/alert"
	"github.com/codingway-hub/a3/internal/server/api/installer"
	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/ingest"
	"github.com/codingway-hub/a3/internal/server/store"
)

// onlineWindow 设备在线判定窗口：最后心跳距今 5 分钟内视为在线。
const onlineWindow = 5 * 60 // 秒

// Router 持有服务端依赖并负责装配 gin 引擎。
type Router struct {
	eventStore      *store.Store
	alertService    *alert.Service
	deviceAPI       *ingest.Handler // 设备侧接入（注册/上报）；nil 则不挂载
	jwtSecret       string
	webDist         string            // 前端静态目录；为空则不托管
	agentDist       string            // 采集器发布产物目录；为空则不提供下载
	publicURL       string            // 对外公开地址（配置即权威，反代场景）；空则按请求 Host 推导
	agentAssetPaths map[string]string // 白名单产物名 → 磁盘路径，启动期建立，绝不拼接用户输入
	version         string            // 服务端版本（healthz/概览展示）
	startedAt       time.Time         // 启动时刻（运行时长计算基准）
}

// RouterConfig 是装配参数。
type RouterConfig struct {
	JWTSecret string
	WebDist   string
	AgentDist string
	PublicURL string
	DeviceAPI *ingest.Handler
	Version   string
}

// NewRouter 构建装配器。
func NewRouter(eventStore *store.Store, alertService *alert.Service, routerConfig RouterConfig) *Router {
	agentAssetPaths := make(map[string]string)
	if routerConfig.AgentDist != "" {
		for _, assetName := range installer.SupportedAssetNames() {
			agentAssetPaths[assetName] = filepath.Join(routerConfig.AgentDist, assetName)
		}
	}
	return &Router{
		eventStore:      eventStore,
		alertService:    alertService,
		deviceAPI:       routerConfig.DeviceAPI,
		jwtSecret:       routerConfig.JWTSecret,
		webDist:         routerConfig.WebDist,
		agentDist:       routerConfig.AgentDist,
		publicURL:       routerConfig.PublicURL,
		agentAssetPaths: agentAssetPaths,
		version:         routerConfig.Version,
		startedAt:       time.Now(),
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

	// 采集器一键安装托管：install.sh 按请求地址注入服务端地址，产物下载走白名单映射（公开，先例 register）
	engine.GET("/install.sh", api.HandleInstallScript)
	engine.GET("/download/agent/:assetName", api.HandleAgentDownload)

	// 存活/就绪探测：DB 可达性判定；基础设施探针与采集器 doctor 免鉴权（先例 install.sh）
	engine.GET("/healthz", api.HandleHealthz)

	// 控制台 API：login 公开，其余统一 JWT 保护；写操作按角色二次收敛
	consoleGroup := engine.Group("/api/v1")
	consoleGroup.POST("/auth/login", api.HandleLogin)
	consoleGroup.GET("/setup-info", api.HandleSetupInfo)
	protectedGroup := consoleGroup.Group("", auth.RequireJWT(api.jwtSecret))
	{
		protectedGroup.GET("/auth/me", api.HandleMe)
		protectedGroup.GET("/stats/overview", api.HandleStatsOverview)
		protectedGroup.GET("/sessions", api.HandleListSessions)
		protectedGroup.GET("/sessions/:deviceId/:sessionKey/events", api.HandleSessionEvents)
		protectedGroup.GET("/sessions/:deviceId/:sessionKey/export", api.HandleSessionExport)
		protectedGroup.GET("/alerts", api.HandleListAlerts)
		// 告警确认是审计员日常工作：admin 与 auditor 均可
		protectedGroup.PATCH("/alerts/:alertID", api.HandleAcknowledgeAlert)
		protectedGroup.GET("/alerts/export", api.HandleAlertsExport)
		protectedGroup.GET("/devices", api.HandleListDevices)
		protectedGroup.GET("/rules", api.HandleListRules)
		protectedGroup.GET("/audit-log", api.HandleListAuditLog)

		// 危险写操作 admin-only：规则变更、设备吊销/恢复、用户管理、安装凭据、设备 Token 轮换
		adminOnlyGroup := protectedGroup.Group("", auth.RequireRole("admin"))
		{
			adminOnlyGroup.POST("/rules", api.HandleCreateRule)
			adminOnlyGroup.PUT("/rules/:ruleID", api.HandleUpdateRule)
			adminOnlyGroup.DELETE("/rules/:ruleID", api.HandleDeleteRule)
			adminOnlyGroup.PATCH("/rules/:ruleID", api.HandlePatchRule)
			adminOnlyGroup.PATCH("/devices/:deviceID", api.HandlePatchDeviceStatus)
			adminOnlyGroup.POST("/devices/:deviceID/token", api.HandleRotateDeviceToken)
			adminOnlyGroup.GET("/credentials", api.HandleListInstallCredentials)
			adminOnlyGroup.POST("/credentials", api.HandleCreateInstallCredential)
			adminOnlyGroup.POST("/credentials/:credentialID/revoke", api.HandleRevokeInstallCredential)
			adminOnlyGroup.GET("/credentials/:credentialID/uses", api.HandleListCredentialUses)
			adminOnlyGroup.GET("/users", api.HandleListUsers)
			adminOnlyGroup.POST("/users", api.HandleCreateUser)
			adminOnlyGroup.PATCH("/users/:userID", api.HandlePatchUser)
			adminOnlyGroup.PATCH("/users/:userID/password", api.HandleResetUserPassword)
		}
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
