package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/store"
)

// usernamePattern 用户名约束：字母/数字/下划线/点/连字符，2-32 字符。
var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{2,32}$`)

// minPasswordLength 口令最短长度。
const minPasswordLength = 8

// validateRole 角色合法性（与迁移 0010 CHECK、auth.validRoles 同源）。
func validateRole(role string) bool {
	return role == "admin" || role == "auditor"
}

// hashPassword 明文口令 → bcrypt 哈希。
func hashPassword(password string) (string, error) {
	passwordHash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(passwordHash), hashErr
}

// userSnapshot 审计快照形状（不含口令哈希）。
func userSnapshot(userRow store.AdminUser) map[string]any {
	return map[string]any{"username": userRow.Username, "role": userRow.Role, "enabled": userRow.Enabled}
}

// logAuditFailure 审计独立事务失败仅记录（留痕尽力而为，不阻断已生效变更）。
func logAuditFailure(action string, targetID string, auditErr error) {
	slog.Warn("审计留痕失败", slog.String("action", action), slog.String("target", targetID), slog.Any("err", auditErr))
}

// HandleListUsers GET /users —— 全部账号（不含口令哈希）。admin-only。
func (api *Router) HandleListUsers(routerCtx *gin.Context) {
	userList, listErr := api.eventStore.ListAdminUsers(routerCtx.Request.Context())
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询用户失败"})
		return
	}
	items := make([]gin.H, 0, len(userList))
	for _, userRow := range userList {
		items = append(items, gin.H{
			"id":         userRow.ID,
			"username":   userRow.Username,
			"role":       userRow.Role,
			"enabled":    userRow.Enabled,
			"created_at": userRow.CreatedAt,
		})
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items})
}

// HandleCreateUser POST /users —— 新建账号并留痕。admin-only。
func (api *Router) HandleCreateUser(routerCtx *gin.Context) {
	var createRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&createRequest); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}
	if !usernamePattern.MatchString(createRequest.Username) {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "用户名需为 2-32 位字母/数字/下划线/点/连字符"})
		return
	}
	if len(createRequest.Password) < minPasswordLength {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "口令至少 8 位"})
		return
	}
	if !validateRole(createRequest.Role) {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "角色仅支持 admin、auditor"})
		return
	}

	passwordHash, hashErr := hashPassword(createRequest.Password)
	if hashErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "口令加密失败"})
		return
	}

	// 建号 + 留痕同事务：账号生效则留痕必在（照 rules/devices WithAudit 先例）
	afterState, _ := json.Marshal(map[string]any{"username": createRequest.Username, "role": createRequest.Role, "enabled": true})
	createErr := api.eventStore.CreateAdminUserWithAudit(routerCtx.Request.Context(),
		createRequest.Username, passwordHash, createRequest.Role, auditOperator(routerCtx), afterState)
	if createErr != nil {
		if errors.Is(createErr, store.ErrAlreadyExists) {
			routerCtx.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
			return
		}
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
		return
	}
	routerCtx.JSON(http.StatusCreated, gin.H{"status": "created"})
}

// HandlePatchUser PATCH /users/:userID —— 停用/启用或改角色并留痕。admin-only。
// 防自锁：不允许对当前登录账号停用或变更自身角色。
// 已知限制：JWT 无状态，停用/降级对已签发旧 token 在过期（≤8h）前不生效，一期接受。
func (api *Router) HandlePatchUser(routerCtx *gin.Context) {
	userID, parseErr := strconv.ParseInt(routerCtx.Param("userID"), 10, 64)
	if parseErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "用户 ID 非法"})
		return
	}
	var patchRequest struct {
		Enabled *bool   `json:"enabled"`
		Role    *string `json:"role"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&patchRequest); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}
	if patchRequest.Role != nil && !validateRole(*patchRequest.Role) {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "角色仅支持 admin、auditor"})
		return
	}
	if patchRequest.Enabled == nil && patchRequest.Role == nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "需提供 enabled 或 role 至少一项"})
		return
	}

	beforeUser, fetchErr := api.eventStore.GetAdminUserByID(routerCtx.Request.Context(), userID)
	if fetchErr != nil {
		if errors.Is(fetchErr, store.ErrNotFound) {
			routerCtx.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
			return
		}
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询用户失败"})
		return
	}

	// 防自锁：对当前登录账号停用或变更角色会把自己锁在外面
	if currentUsername, hasUsername := auth.UsernameFrom(routerCtx); hasUsername && currentUsername == beforeUser.Username {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "不能停用或变更自身账号，请用其他管理员账号操作"})
		return
	}

	beforeState, _ := json.Marshal(userSnapshot(beforeUser))
	var updateErr error
	afterUser := beforeUser
	switch {
	case patchRequest.Enabled != nil:
		afterUser, updateErr = api.eventStore.SetAdminUserEnabled(routerCtx.Request.Context(), userID, *patchRequest.Enabled)
	case patchRequest.Role != nil:
		afterUser, updateErr = api.eventStore.SetAdminUserRole(routerCtx.Request.Context(), userID, *patchRequest.Role)
	}
	if updateErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户失败"})
		return
	}

	afterState, _ := json.Marshal(userSnapshot(afterUser))
	if auditErr := api.eventStore.AppendAudit(routerCtx.Request.Context(),
		store.AuditActionUserUpdate, store.AuditTargetUser, beforeUser.Username,
		auditOperator(routerCtx), beforeState, afterState); auditErr != nil {
		logAuditFailure(store.AuditActionUserUpdate, beforeUser.Username, auditErr)
	}
	routerCtx.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// HandleResetUserPassword PATCH /users/:userID/password —— 重置口令并留痕。admin-only。
func (api *Router) HandleResetUserPassword(routerCtx *gin.Context) {
	userID, parseErr := strconv.ParseInt(routerCtx.Param("userID"), 10, 64)
	if parseErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "用户 ID 非法"})
		return
	}
	var resetRequest struct {
		Password string `json:"password"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&resetRequest); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}
	if len(resetRequest.Password) < minPasswordLength {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "口令至少 8 位"})
		return
	}

	passwordHash, hashErr := hashPassword(resetRequest.Password)
	if hashErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "口令加密失败"})
		return
	}

	_, resetErr := api.eventStore.ResetAdminUserPasswordWithAudit(routerCtx.Request.Context(),
		userID, passwordHash, auditOperator(routerCtx))
	if resetErr != nil {
		if errors.Is(resetErr, store.ErrNotFound) {
			routerCtx.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
			return
		}
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "重置口令失败"})
		return
	}
	routerCtx.JSON(http.StatusOK, gin.H{"status": "updated"})
}
