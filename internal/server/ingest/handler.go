package ingest

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/store"
)

// registerBodyLimit 注册请求体大小上限（含五字段与安装凭据，16KB 绰绰有余）。
const registerBodyLimit = 16 << 10

// registerRateCapacity / registerRateRefill 注册限流：每 IP 突发 10 次、其后
// 每 10 秒恢复 1 次——覆盖批量装机又不至于被爆破凭据占用消耗。
const (
	registerRateCapacity = 10
	registerRateRefill   = 10 * time.Second
)

// Handler 是终端接入 HTTP 层：路由挂载与错误码映射。
type Handler struct {
	service    *Service
	rateLimiter *ipRateLimiter
}

// NewHandler 构建接入 handler。
func NewHandler(service *Service) *Handler {
	return &Handler{
		service:     service,
		rateLimiter: newIPRateLimiter(registerRateCapacity, registerRateRefill),
	}
}

// RegisterRoutes 注册设备侧路由：
//   - POST /api/v1/devices/register（公开，凭据门禁：管理员一次性安装代码）
//
// 携 Token 路由由装配方挂在 RequireDeviceToken 中间件之后：
//   - POST /api/v1/events/batch
//   - GET  /api/v1/devices/rules（规则中心下发：终端常驻进程周期拉取）
//   - POST /api/v1/agent/heartbeat（常驻心跳：刷新在线态 + 上报 spool 积压）
func (handler *Handler) RegisterRoutes(router gin.IRouter) {
	router.POST("/api/v1/devices/register", handler.HandleRegister)
	router.POST("/api/v1/events/batch", auth.RequireDeviceToken(handler.service.eventStore), handler.HandleEventsBatch)
	router.GET("/api/v1/devices/rules", auth.RequireDeviceToken(handler.service.eventStore), handler.HandleDeviceRules)
	router.POST("/api/v1/agent/heartbeat", auth.RequireDeviceToken(handler.service.eventStore), handler.HandleHeartbeat)
}

// HandleRegister 处理设备注册（统一门禁=管理员一次性安装凭据）：
// 先限流（429）→ 请求体大小限制（413）→ 字段/凭据校验（400/403）→ 指纹注册复用。
// await 携带可选 Bearer 凭证：同指纹复用身份必须证明持有既有 Token。
func (handler *Handler) HandleRegister(routerCtx *gin.Context) {
	clientIP := routerCtx.ClientIP()
	if !handler.rateLimiter.Allow(clientIP) {
		// 限流事件也留痕（无关联凭据）：便于观察是否有爆破尝试。
		if _, recordErr := handler.service.eventStore.RecordCredentialUse(
			routerCtx.Request.Context(), 0, store.CredentialOutcomeRateLimited, "", clientIP); recordErr != nil {
			// 记录失败不阻断限流响应
			_ = recordErr
		}
		routerCtx.JSON(http.StatusTooManyRequests, gin.H{"error": ErrRateLimited.Error()})
		return
	}

	routerCtx.Request.Body = http.MaxBytesReader(routerCtx.Writer, routerCtx.Request.Body, registerBodyLimit)
	var registerInput RegisterInput
	if bindErr := routerCtx.ShouldBindJSON(&registerInput); bindErr != nil {
		status := http.StatusBadRequest
		var maxBytesErr *http.MaxBytesError
		if errors.As(bindErr, &maxBytesErr) {
			status = http.StatusRequestEntityTooLarge
		}
		routerCtx.JSON(status, gin.H{"error": "请求体不合法或过大"})
		return
	}

	registerResult, registerErr := handler.service.RegisterDevice(
		routerCtx.Request.Context(), registerInput, auth.BearerTokenFrom(routerCtx), clientIP)
	switch {
	case registerErr == nil:
		routerCtx.JSON(http.StatusOK, gin.H{"device_id": registerResult.DeviceID, "token": registerResult.Token})
	case errors.Is(registerErr, ErrCredentialExpired):
		routerCtx.JSON(http.StatusForbidden, gin.H{"error": ErrCredentialExpired.Error()})
	case errors.Is(registerErr, ErrCredentialDisabled):
		routerCtx.JSON(http.StatusForbidden, gin.H{"error": ErrCredentialDisabled.Error()})
	case errors.Is(registerErr, ErrCredentialUsedUp):
		routerCtx.JSON(http.StatusForbidden, gin.H{"error": ErrCredentialUsedUp.Error()})
	case errors.Is(registerErr, ErrCredentialInvalid), errors.Is(registerErr, ErrCredentialUnknown):
		routerCtx.JSON(http.StatusForbidden, gin.H{"error": "安装凭据无效，请联系管理员重新生成"})
	case errors.Is(registerErr, store.ErrCredentialMismatch):
		routerCtx.JSON(http.StatusForbidden, gin.H{"error": "携带的 Token 与设备不符，拒绝复用身份"})
	case errors.Is(registerErr, store.ErrCredentialRequired):
		routerCtx.JSON(http.StatusConflict, gin.H{"error": "设备已存在：注册须携带当前 Token 以证明身份（或联系管理员吊销后重新注册）"})
	case errors.Is(registerErr, ErrEventInvalid):
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": registerErr.Error()})
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "注册失败，请稍后重试"})
	}
}

// HandleEventsBatch 处理事件批量上报（前置 RequireDeviceToken 中间件）。
func (handler *Handler) HandleEventsBatch(routerCtx *gin.Context) {
	deviceRow, hasDevice := auth.DeviceFrom(routerCtx)
	if !hasDevice {
		routerCtx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "设备身份缺失"})
		return
	}
	var envelope BatchEnvelope
	if bindErr := routerCtx.ShouldBindJSON(&envelope); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}

	batchResult, submitErr := handler.service.SubmitEvents(routerCtx.Request.Context(), deviceRow, envelope)
	switch {
	case submitErr == nil:
		routerCtx.JSON(http.StatusOK, batchResult)
	case errors.Is(submitErr, ErrEventInvalid), errors.Is(submitErr, ErrBatchTooLarge):
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": submitErr.Error()})
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "事件入库失败，请整批重试"})
	}
}

// HandleDeviceRules 下发当前启用中的规则全集（前置 RequireDeviceToken 中间件）。
// 响应含 revision 内容摘要，终端按其做变更检测；替换制语义——该响应即终端
// 规则集的权威来源（快照缺失时终端才回落内置清单）。
func (handler *Handler) HandleDeviceRules(routerCtx *gin.Context) {
	if _, hasDevice := auth.DeviceFrom(routerCtx); !hasDevice {
		routerCtx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "设备身份缺失"})
		return
	}
	rulesPayload, buildErr := handler.service.BuildDeviceRules(routerCtx.Request.Context())
	if buildErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "组装下发规则失败"})
		return
	}
	routerCtx.JSON(http.StatusOK, rulesPayload)
}

// HandleHeartbeat 处理常驻心跳上报（前置 RequireDeviceToken 中间件）：
// 刷新设备 last_seen 并把终端带外积压（断网缓存未送达的批次数/字节数）落库，
// 供控制台 online/abnormal 判定。body {spool_pending_batches, spool_pending_bytes}，
// 字段必须为非负整数；心跳不产生事件、不触发告警。
func (handler *Handler) HandleHeartbeat(routerCtx *gin.Context) {
	deviceRow, hasDevice := auth.DeviceFrom(routerCtx)
	if !hasDevice {
		routerCtx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "设备身份缺失"})
		return
	}
	var heartbeatInput struct {
		SpoolPendingBatches int64 `json:"spool_pending_batches"`
		SpoolPendingBytes   int64 `json:"spool_pending_bytes"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&heartbeatInput); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}
	if heartbeatInput.SpoolPendingBatches < 0 || heartbeatInput.SpoolPendingBytes < 0 {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "积压字段必须为非负整数"})
		return
	}
	if heartbeatErr := handler.service.eventStore.TouchDeviceHeartbeat(routerCtx.Request.Context(),
		deviceRow.DeviceID, heartbeatInput.SpoolPendingBatches, heartbeatInput.SpoolPendingBytes); heartbeatErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "心跳写入失败"})
		return
	}
	routerCtx.JSON(http.StatusOK, gin.H{"ok": true, "device_id": deviceRow.DeviceID})
}