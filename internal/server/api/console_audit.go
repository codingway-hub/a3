package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/store"
)

// auditActionLabels 审计动作的中文展示标签（响应中同时给出原始 action）。
var auditActionLabels = map[string]string{
	store.AuditActionRuleCreate:    "新建规则",
	store.AuditActionRuleUpdate:    "修改规则",
	store.AuditActionRulePatch:     "启停规则",
	store.AuditActionRuleDelete:    "删除规则",
	store.AuditActionDeviceRevoke:  "吊销设备",
	store.AuditActionDeviceRestore: "恢复设备",
}

// HandleListAuditLog GET /audit-log?target_type=&target_id=&page=&page_size=
// —— 控制台敏感操作留痕（规则 CRUD/启停、设备吊销/恢复），created_at 倒序分页。
func (api *Router) HandleListAuditLog(routerCtx *gin.Context) {
	filter := store.AuditFilter{
		TargetType: routerCtx.Query("target_type"),
		TargetID:   routerCtx.Query("target_id"),
		Page:       parsePositiveIntQuery(routerCtx, "page", 1),
		PageSize:   parsePositiveIntQuery(routerCtx, "page_size", 20),
	}

	entries, totalCount, listErr := api.eventStore.ListAuditLog(routerCtx.Request.Context(), filter)
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询审计日志失败"})
		return
	}

	items := make([]gin.H, 0, len(entries))
	for _, entry := range entries {
		var beforeState any
		var afterState any
		_ = json.Unmarshal(entry.Before, &beforeState)
		_ = json.Unmarshal(entry.After, &afterState)
		items = append(items, gin.H{
			"id":           entry.ID,
			"action":       entry.Action,
			"action_label": auditActionLabels[entry.Action],
			"target_type":  entry.TargetType,
			"target_id":    entry.TargetID,
			"operator":     entry.Operator,
			"before":       beforeState,
			"after":        afterState,
			"created_at":   entry.CreatedAt,
		})
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items, "total": totalCount})
}
