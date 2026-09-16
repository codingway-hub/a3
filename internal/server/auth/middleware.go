package auth

import (
	"context"
	"strings"
	"time"

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

// SessionAuthStore 是 RequireJWT 查询会话签发时账号态（启用 + 代际号）的最小接口。
// *store.Store 满足；鉴权中间件依赖它完成「停用/改角色/重置口令立即吊销会话」，
// 测试可用内存桩替代避免依赖数据库。
type SessionAuthStore interface {
	GetAdminUserSessionState(ctx context.Context, username string) (enabled bool, tokenVersion int64, err error)
}

// RequireDeviceToken 校验 Bearer 设备 Token：哈希反查 devices 表，
// 命中且设备为 active、Token 未到期时把 *store.Device 挂入上下文；
// 未命中/已吊销/已禁用/已过期/格式非法一律 401。
// 吊销与禁用即生效：状态非法设备的 Token 立即可用性切断，自有审计数据原样保留。
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
			ctx.AbortWithStatusJSON(401, gin.H{"error": "设备已吊销或禁用，请联系管理员"})
			return
		}
		// 到期校验：TTL 配置后注册/换发的 Token 带到期时间，过期即拒绝（重新注册或管理员换发前不可用）
		if device.TokenExpiresAt != nil && time.Now().After(*device.TokenExpiresAt) {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "设备 Token 已过期，请联系管理员换发"})
			return
		}
		ctx.Set(contextKeyDevice, device)
		ctx.Next()
	}
}

// RequireJWT 校验控制台 JWT 并比对签发时代际号与账号态：
//   - 签名/有效期/角色校验失败 → 401；
//   - 账号不存在/已停用/代际号不符（状态在签发后被变更）→ 401。
//
// 通过后把用户名与角色挂入上下文。代际号比对使停用、降级、重置口令立即作废
// 全部已签发会话，不再依赖 JWT 自然过期（≤8h）。
func RequireJWT(secret string, sessionStore SessionAuthStore) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, hasToken := extractBearerToken(ctx)
		if !hasToken {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "未登录"})
			return
		}
		username, role, tokenVersion, verifyErr := VerifyJWT(secret, token)
		if verifyErr != nil {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "登录已失效，请重新登录"})
			return
		}
		enabled, currentVersion, lookupErr := sessionStore.GetAdminUserSessionState(ctx.Request.Context(), username)
		if lookupErr != nil || !enabled {
			// 账号被删/查询失败/已停用一律按失效处理，不泄露具体原因
			ctx.AbortWithStatusJSON(401, gin.H{"error": "登录已失效，请重新登录"})
			return
		}
		// 代际校验：账号状态变更（停用/改角色/重置口令）自增 token_version，
		// 签发早于变更的 JWT 立即失效——不再等到自然过期
		if tokenVersion != currentVersion {
			ctx.AbortWithStatusJSON(401, gin.H{"error": "登录已失效，请重新登录"})
			return
		}
		ctx.Set(contextKeyUsername, username)
		ctx.Set(contextKeyRole, role)
		ctx.Next()
	}
}

// RequireRole 限制控制台角色：JWT 上下文中的 role 不在允许集合内一律 403。
// 角色越权的旧签名 token 已被 RequireJWT 的代际号校验拦截（改角色即自增版本），
// 此处为纵深防御：即使代际号校验异常，仍按 role 二次收敛。
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
