package auth

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/store"
)

// contextKeyDevice / contextKeyUsername 是 gin.Context 存取鉴权主体的键名。
const (
	contextKeyDevice    = "auth.device"
	contextKeyUsername  = "auth.username"
	authorizationPrefix = "Bearer "
)

// RequireDeviceToken 校验 Bearer 设备 Token：哈希反查 devices 表，
// 命中后把 *store.Device 挂入上下文；未命中/格式非法一律 401。
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
		ctx.Set(contextKeyDevice, device)
		ctx.Next()
	}
}

// RequireJWT 校验控制台 JWT；通过后把用户名挂入上下文。
func RequireJWT(secret string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, hasToken := extractBearerToken(ctx)
		if !hasToken {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "未登录"})
			return
		}
		username, verifyErr := VerifyJWT(secret, token)
		if verifyErr != nil {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "登录已失效，请重新登录"})
			return
		}
		ctx.Set(contextKeyUsername, username)
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
