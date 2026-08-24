package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/store"
)

// HandleListRules GET /rules —— 规则全集（含停用）。
func (api *Router) HandleListRules(routerCtx *gin.Context) {
	ruleRecords, listErr := api.eventStore.ListRules(routerCtx.Request.Context())
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询规则失败"})
		return
	}

	items := make([]gin.H, 0, len(ruleRecords))
	for _, ruleRecord := range ruleRecords {
		items = append(items, gin.H{
			"id":         ruleRecord.ID,
			"name":       ruleRecord.Name,
			"category":   ruleRecord.Category,
			"matcher":    json.RawMessage(ruleRecord.Matcher),
			"severity":   ruleRecord.Severity,
			"action":     ruleRecord.Action,
			"enabled":    ruleRecord.Enabled,
			"builtin":    ruleRecord.Builtin,
			"updated_at": ruleRecord.UpdatedAt,
		})
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items})
}

// HandlePatchRule PATCH /rules/:ruleID {"enabled":true|false} —— 启停规则并热更新扫描引擎。
func (api *Router) HandlePatchRule(routerCtx *gin.Context) {
	var patchRequest struct {
		Enabled *bool `json:"enabled"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&patchRequest); bindErr != nil || patchRequest.Enabled == nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体需包含 enabled 布尔字段"})
		return
	}
	ctx := routerCtx.Request.Context()

	patchErr := api.eventStore.SetRuleEnabled(ctx, routerCtx.Param("ruleID"), *patchRequest.Enabled)
	switch {
	case patchErr == nil:
	case errors.Is(patchErr, store.ErrNotFound):
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "更新规则失败"})
		return
	}

	// 规则启停后立即重载扫描引擎，保证策略即时生效
	if reloadErr := api.alertService.ReloadRules(ctx); reloadErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "规则已更新但扫描引擎重载失败"})
		return
	}
	routerCtx.JSON(http.StatusOK, gin.H{"id": routerCtx.Param("ruleID"), "enabled": *patchRequest.Enabled})
}
