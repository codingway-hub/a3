package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/codingway-hub/a3/internal/server/auth"
)

// compareBcrypt 比对口令与其 bcrypt 哈希。
func compareBcrypt(passwordHash string, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) == nil
}

// consoleSessionTTL 控制台会话有效期（一期约定 8 小时）。
const consoleSessionTTL = 8 * time.Hour

// HandleLogin 控制台登录：比对种子管理员凭证，签发 HS256 JWT。
func (api *Router) HandleLogin(routerCtx *gin.Context) {
	var loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&loginRequest); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}

	if !api.verifyAdminCredentials(loginRequest.Username, loginRequest.Password) {
		routerCtx.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	tokenString, signErr := auth.SignJWT(api.jwtSecret, loginRequest.Username, consoleSessionTTL)
	if signErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "签发会话失败"})
		return
	}
	routerCtx.JSON(http.StatusOK, gin.H{
		"token":      tokenString,
		"expires_in": int(consoleSessionTTL.Seconds()),
		"username":   loginRequest.Username,
	})
}

// verifyAdminCredentials 校验用户名与 bcrypt 口令哈希；恒时比较由 bcrypt 提供。
func (api *Router) verifyAdminCredentials(username string, password string) bool {
	if username == "" || password == "" {
		return false
	}
	if username != api.adminUsername {
		// 仍执行一次哈希比较，避免按用户名分支的时序差异
		_ = compareBcrypt(api.adminPasswordHash, "timing-equalizer")
		return false
	}
	return compareBcrypt(api.adminPasswordHash, password)
}

// HandleMe 返回当前登录用户。
func (api *Router) HandleMe(routerCtx *gin.Context) {
	username, hasUsername := auth.UsernameFrom(routerCtx)
	if !hasUsername {
		routerCtx.JSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
		return
	}
	routerCtx.JSON(http.StatusOK, gin.H{"username": username})
}
