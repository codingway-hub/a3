package ingest

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/auth"
)

// Handler 是终端接入 HTTP 层：路由挂载与错误码映射。
type Handler struct {
	service *Service
}

// NewHandler 构建接入 handler。
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes 注册设备侧路由：
//   - POST /api/v1/devices/register（公开，是否放行由服务端开关决定）
//
// 事件上报路由由装配方挂在 RequireDeviceToken 中间件之后：
//   - POST /api/v1/events/batch
func (handler *Handler) RegisterRoutes(router gin.IRouter) {
	router.POST("/api/v1/devices/register", handler.HandleRegister)
	router.POST("/api/v1/events/batch", auth.RequireDeviceToken(handler.service.eventStore), handler.HandleEventsBatch)
}

// HandleRegister 处理设备注册；403=未开放自动注册，400=请求不合法。
func (handler *Handler) HandleRegister(routerCtx *gin.Context) {
	var registerInput RegisterInput
	if bindErr := routerCtx.ShouldBindJSON(&registerInput); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}
	registerResult, registerErr := handler.service.RegisterDevice(routerCtx.Request.Context(), registerInput)
	switch {
	case registerErr == nil:
		routerCtx.JSON(http.StatusOK, gin.H{"device_id": registerResult.DeviceID, "token": registerResult.Token})
	case errors.Is(registerErr, ErrAutoRegisterDisabled):
		routerCtx.JSON(http.StatusForbidden, gin.H{"error": "自动注册未开放，请联系管理员预生成 Token"})
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
