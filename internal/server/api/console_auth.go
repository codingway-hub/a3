package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/store"
)

// compareBcrypt 比对口令与其 bcrypt 哈希。
func compareBcrypt(passwordHash string, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) == nil
}

// consoleSessionTTL 控制台会话有效期（一期约定 8 小时）。
const consoleSessionTTL = 8 * time.Hour

// dummyBcryptHash 对固定串预生成的哈希：用户名不存在时仍执行一次哈希比较，
// 抹平「按用户名分支」的时序差异（照 verifyAdminCredentials 时代 timing-equalizer 先例）。
var dummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer"), bcrypt.DefaultCost)

// HandleLogin 控制台登录：查 admin_users 校验口令与启用状态，签发带角色的 HS256 JWT。
func (api *Router) HandleLogin(routerCtx *gin.Context) {
	var loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&loginRequest); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}

	userRow, lookupErr := api.eventStore.GetAdminUserByUsername(routerCtx.Request.Context(), loginRequest.Username)
	if lookupErr != nil {
		if !errors.Is(lookupErr, store.ErrNotFound) {
			routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "登录失败"})
			return
		}
		// 用户不存在：仍比一次哈希防时序侧信道，然后统一报凭据错误
		_ = compareBcrypt(string(dummyBcryptHash), "timing-equalizer")
		routerCtx.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}
	if !userRow.Enabled {
		routerCtx.JSON(http.StatusUnauthorized, gin.H{"error": "账号已停用，请联系管理员"})
		return
	}
	if !compareBcrypt(userRow.PasswordHash, loginRequest.Password) {
		routerCtx.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	tokenString, signErr := auth.SignJWT(api.jwtSecret, userRow.Username, userRow.Role, consoleSessionTTL)
	if signErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "签发会话失败"})
		return
	}
	routerCtx.JSON(http.StatusOK, gin.H{
		"token":      tokenString,
		"expires_in": int(consoleSessionTTL.Seconds()),
		"username":   userRow.Username,
		"role":       userRow.Role,
	})
}

// HandleMe 返回当前登录用户与角色。
func (api *Router) HandleMe(routerCtx *gin.Context) {
	username, hasUsername := auth.UsernameFrom(routerCtx)
	role, hasRole := auth.RoleFrom(routerCtx)
	if !hasUsername || !hasRole {
		routerCtx.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	routerCtx.JSON(http.StatusOK, gin.H{"username": username, "role": role})
}
