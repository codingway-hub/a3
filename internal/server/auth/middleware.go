package auth

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/store"
)

// contextKeyDevice / contextKeyUsername / contextKeyRole 是 gin.Context 存取鉴权主体的键名。
const (
	contextKeyDevice    = "auth.device"
	contextKeyUsername  = "auth.username"
	contextKeyRole      = "auth.role"
	authorizationPrefix = "Bearer "
)

// RequireDeviceToken 校验 Bearer 设备 Token：哈希反查 devices 表，
// 命中且设备为 active 时把 *store.Device 挂入上下文；未命中/已吊销/格式非法一律 401。
// 吊销即生效：revoked 设备的 Token 立即可用性切断，自有审计数据原样保留。
func RequireDeviceToken(deviceStore *store.Store) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, hasToken := extractBearerToken(ctx)
		if !hasToken {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "缺少设备 Token"})
			return
		}
		device, lookupErr := deviceStore.GetDeviceByTokenHash(ctx.Request.Context(), HashToken(token))
		if lookupErr != nil {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "设备 Token 无效"})
			return
		}
		if device.Status != "active" {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "设备已吊销，请联系管理员"})
			return
		}
		ctx.Set(contextKeyDevice, device)
		ctx.Next()
	}
}

// RequireJWT 校验控制台 JWT；通过后把用户名与角色挂入上下文。
func RequireJWT(secret string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, hasToken := extractBearerToken(ctx)
		if !hasToken {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "未登录"})
			return
		}
		username, role, verifyErr := VerifyJWT(secret, token)
		if verifyErr != nil {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "登录已失效，请重新登录"})
			return
		}
		ctx.Set(contextKeyUsername, username)
		ctx.Set(contextKeyRole, role)
		ctx.Next()
	}
}

// RequireRole 限制控制台角色：JWT 上下文中的 role 不在允许集合内一律 403。
// 已知限制：JWT 无状态，停用/降级对已签发 token 在过期（≤8h）前不生效，一期接受。
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	allowedSet := make(map[string]bool, len(allowedRoles))
	for _, allowedRole := range allowedRoles {
		allowedSet[allowedRole] = true
	}
	return func(ctx *gin.Context) {
		role, hasRole := RoleFrom(ctx)
		if !hasRole || !allowedSet[role] {
			ctx.AbortWithStatusJSON(403, gin.H{"error": "权限不足"})
			return
		}
		ctx.Next()
	}
}

// DeviceFrom 返回中间件挂载的设备信息（仅设备路由的 handler 内可用）。
func DeviceFrom(ctx *gin.Context) (*store.Device, bool) {
	value, exists := ctx.Get(contextKeyDevice)
	if !exists {
		return nil, false
	}
	device, ok := value.(*store.Device)
	return device, ok
}

// UsernameFrom 返回中间件挂载的控制台用户名。
func UsernameFrom(ctx *gin.Context) (string, bool) {
	value, exists := ctx.Get(contextKeyUsername)
	if !exists {
		return "", false
	}
	username, ok := value.(string)
	return username, ok
}

// RoleFrom 返回中间件挂载的控制台角色。
func RoleFrom(ctx *gin.Context) (string, bool) {
	value, exists := ctx.Get(contextKeyRole)
	if !exists {
		return "", false
	}
	role, ok := value.(string)
	return role, ok
}

// extractBearerToken 从 Authorization 头提取 Bearer 凭证。
func extractBearerToken(ctx *gin.Context) (string, bool) {
	headerValue := ctx.GetHeader("Authorization")
	if !strings.HasPrefix(headerValue, authorizationPrefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(headerValue, authorizationPrefix))
	if token == "" {
		return "", false
	}
	return token, true
}

// BearerTokenFrom 非强制提取 Authorization Bearer 凭证（如注册请求的可选凭证证明）；
// 格式非法或缺失返回空串，不报错。
func BearerTokenFrom(ctx *gin.Context) string {
	token, hasToken := extractBearerToken(ctx)
	if !hasToken {
		return ""
	}
	return token
}
