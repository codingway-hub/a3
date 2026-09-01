package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/store"
)

// 安装凭据（注册门禁）控制台端点：admin 生成/吊销/查看使用记录。
// 与用户管理同源的安全模型：明文代码仅在生成响应中出现一次，库中只存哈希。

// 凭据创建参数合法区间：有效期 1 分钟 ~ 1 年，用量 1 ~ 10000，scope 目前仅 device。
const (
	credentialTTLMinMinutes = 1
	credentialTTLMaxMinutes = 525600
	credentialMaxUsesMin    = 1
	credentialMaxUsesMax    = 10000
)

// HandleListInstallCredentials GET /credentials —— 全部安装凭据（不含明文代码）。admin-only。
func (api *Router) HandleListInstallCredentials(routerCtx *gin.Context) {
	credentialList, listErr := api.eventStore.ListInstallCredentials(routerCtx.Request.Context())
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询安装凭据失败"})
		return
	}
	items := make([]gin.H, 0, len(credentialList))
	for _, credential := range credentialList {
		items = append(items, gin.H{
			"id":         credential.ID,
			"code_hint":  credential.CodeHint,
			"scope":      credential.Scope,
			"expires_at": credential.ExpiresAt,
			"max_uses":   credential.MaxUses,
			"uses_count": credential.UsesCount,
			"enabled":    credential.Enabled,
			"created_by": credential.CreatedBy,
			"created_at": credential.CreatedAt,
		})
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items})
}

// HandleCreateInstallCredential POST /credentials —— 生成一次性安装凭据并留痕。
// body：{expires_in_minutes, max_uses, scope}；明文代码仅本次响应返回，务必即时抄送。
// admin-only。
func (api *Router) HandleCreateInstallCredential(routerCtx *gin.Context) {
	operator, hasOperator := auth.UsernameFrom(routerCtx)
	if !hasOperator {
		routerCtx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "登录状态缺失"})
		return
	}

	var createRequest struct {
		ExpiresInMinutes int    `json:"expires_in_minutes"`
		MaxUses          int    `json:"max_uses"`
		Scope            string `json:"scope"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&createRequest); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}
	if createRequest.ExpiresInMinutes < credentialTTLMinMinutes || createRequest.ExpiresInMinutes > credentialTTLMaxMinutes {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "有效期需在 1 分钟 ~ 1 年之间"})
		return
	}
	if createRequest.MaxUses < credentialMaxUsesMin || createRequest.MaxUses > credentialMaxUsesMax {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "用量限制需在 1 ~ 10000 之间"})
		return
	}
	scope := createRequest.Scope
	if scope == "" {
		scope = "device"
	}
	if scope != "device" {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "scope 仅支持 device"})
		return
	}

	// 生成明文代码 → 仅存哈希；after 快照不含代码明文
	code, generateErr := auth.GenerateInstallCode()
	if generateErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "生成安装凭据失败"})
		return
	}
	expiresAt := time.Now().Add(time.Duration(createRequest.ExpiresInMinutes) * time.Minute)
	afterState, _ := json.Marshal(map[string]any{
		"scope":   scope,
		"max_uses": createRequest.MaxUses,
		"expires_in_minutes": createRequest.ExpiresInMinutes,
	})
	credential, createErr := api.eventStore.CreateInstallCredentialWithAudit(
		routerCtx.Request.Context(), auth.HashToken(code), scope, expiresAt,
		createRequest.MaxUses, operator, operator, afterState)
	if createErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "创建安装凭据失败"})
		return
	}

	routerCtx.JSON(http.StatusCreated, gin.H{
		"id":         credential.ID,
		"scope":      credential.Scope,
		"expires_at": credential.ExpiresAt,
		"max_uses":   credential.MaxUses,
		"code":       code, // 明文仅此一次
	})
}

// HandleRevokeInstallCredential POST /credentials/:credentialID/revoke —— 吊销（停用）。
// 吊销即生效：接下来的注册消费命中 rejected_disabled；已留存使用记录原样保留。admin-only。
func (api *Router) HandleRevokeInstallCredential(routerCtx *gin.Context) {
	operator, hasOperator := auth.UsernameFrom(routerCtx)
	if !hasOperator {
		routerCtx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "登录状态缺失"})
		return
	}
	credentialID, parseErr := strconv.ParseInt(routerCtx.Param("credentialID"), 10, 64)
	if parseErr != nil || credentialID <= 0 {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "无效的凭据 ID"})
		return
	}
	revokeErr := api.eventStore.RevokeInstallCredentialWithAudit(
		routerCtx.Request.Context(), credentialID, operator)
	switch {
	case revokeErr == nil:
		routerCtx.JSON(http.StatusOK, gin.H{"id": credentialID, "enabled": false})
	case errors.Is(revokeErr, store.ErrNotFound):
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "凭据不存在或已停用"})
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "吊销失败"})
	}
}

// HandleListCredentialUses GET /credentials/:credentialID/uses —— 该凭据的使用记录
//（成功/拒绝原因/设备归属）。admin-only。
func (api *Router) HandleListCredentialUses(routerCtx *gin.Context) {
	credentialID, parseErr := strconv.ParseInt(routerCtx.Param("credentialID"), 10, 64)
	if parseErr != nil || credentialID <= 0 {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "无效的凭据 ID"})
		return
	}
	page, _ := strconv.Atoi(routerCtx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(routerCtx.DefaultQuery("page_size", "20"))

	useList, totalCount, listErr := api.eventStore.ListCredentialUses(
		routerCtx.Request.Context(), credentialID, page, pageSize)
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询使用记录失败"})
		return
	}
	items := make([]gin.H, 0, len(useList))
	for _, useRow := range useList {
		items = append(items, gin.H{
			"id":         useRow.ID,
			"outcome":    useRow.Outcome,
			"device_id":  useRow.DeviceID,
			"client_ip":  useRow.ClientIP,
			"created_at": useRow.CreatedAt,
		})
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items, "total": totalCount})
}

// HandleRotateDeviceToken POST /devices/:deviceID/token —— 管理员批准换发设备 Token。
// 终端侧重复注册/重装不再轮换 Token（见 RegisterDeviceAtomic），本端点为主机丢失
// 令牌时人工恢复的受控通道：换发后旧 Token 立即失效，新 Token 明文仅此一次返回，
// 待管理员人工转交设备主。admin-only，落 device_token_rotate 审计。
func (api *Router) HandleRotateDeviceToken(routerCtx *gin.Context) {
	operator, hasOperator := auth.UsernameFrom(routerCtx)
	if !hasOperator {
		routerCtx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "登录状态缺失"})
		return
	}
	deviceID := routerCtx.Param("deviceID")
	newToken, generateErr := auth.GenerateDeviceToken()
	if generateErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "生成设备 Token 失败"})
		return
	}
	rotateErr := api.eventStore.RotateDeviceTokenWithAudit(
		routerCtx.Request.Context(), deviceID, auth.HashToken(newToken), operator)
	switch {
	case rotateErr == nil:
		routerCtx.JSON(http.StatusOK, gin.H{"device_id": deviceID, "token": newToken})
	case errors.Is(rotateErr, store.ErrNotFound):
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "设备不存在或已吊销"})
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "轮换失败"})
	}
}