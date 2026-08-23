package api

import (
	"bytes"
	"encoding/csv"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/store"
)

// neutralizeCSVFormulaPrefix 以 = + - @ 开头的单元格前置单引号，防止 Excel/WPS 公式注入。
func neutralizeCSVFormulaPrefix(cellText string) string {
	if len(cellText) == 0 {
		return cellText
	}
	switch cellText[0] {
	case '=', '+', '-', '@':
		return "'" + cellText
	}
	return cellText
}

// buildAlertsCSV 把告警列表渲染为 CSV 字节（表头 + 行，时间 RFC3339）；summary 列做公式注入防护。
func buildAlertsCSV(alertList []store.Alert) []byte {
	csvBuffer := &bytes.Buffer{}
	csvWriter := csv.NewWriter(csvBuffer)
	_ = csvWriter.Write([]string{"id", "created_at", "severity", "rule_id", "rule_name",
		"device_id", "session_key", "status", "summary"})
	for _, alertRow := range alertList {
		_ = csvWriter.Write([]string{
			alertRow.ID,
			alertRow.CreatedAt.Format(time.RFC3339),
			alertRow.Severity,
			alertRow.RuleID,
			alertRow.RuleName,
			alertRow.DeviceID,
			alertRow.SessionKey,
			alertRow.Status,
			neutralizeCSVFormulaPrefix(alertRow.Summary),
		})
	}
	csvWriter.Flush()
	return csvBuffer.Bytes()
}

// HandleListAlerts GET /alerts?status=&severity=&page=&page_size=
func (api *Router) HandleListAlerts(routerCtx *gin.Context) {
	alertFilter := store.AlertFilter{
		Status:   routerCtx.Query("status"),
		Severity: routerCtx.Query("severity"),
		Page:     parsePositiveIntQuery(routerCtx, "page", 1),
		PageSize: parsePositiveIntQuery(routerCtx, "page_size", 20),
	}
	alertList, totalCount, listErr := api.eventStore.ListAlerts(routerCtx.Request.Context(), alertFilter)
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询告警失败"})
		return
	}

	items := make([]gin.H, 0, len(alertList))
	for _, alertRow := range alertList {
		items = append(items, alertToJSON(alertRow))
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items, "total": totalCount})
}

// HandleAcknowledgeAlert PATCH /alerts/:alertID {"status":"acknowledged"} —— 确认告警。
func (api *Router) HandleAcknowledgeAlert(routerCtx *gin.Context) {
	var patchRequest struct {
		Status string `json:"status"`
	}
	if bindErr := routerCtx.ShouldBindJSON(&patchRequest); bindErr != nil || patchRequest.Status != "acknowledged" {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "仅支持 status=acknowledged 的确认操作"})
		return
	}

	ackErr := api.eventStore.AcknowledgeAlert(routerCtx.Request.Context(), routerCtx.Param("alertID"))
	switch {
	case ackErr == nil:
		routerCtx.JSON(http.StatusOK, gin.H{"status": "acknowledged"})
	case errors.Is(ackErr, store.ErrNotFound):
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "告警不存在"})
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "确认告警失败"})
	}
}

// HandleAlertsExport GET /alerts/export?status=&severity= —— CSV 下载（全量，不截断）。
func (api *Router) HandleAlertsExport(routerCtx *gin.Context) {
	alertList, exportErr := api.eventStore.ListAlertsForExport(routerCtx.Request.Context(),
		routerCtx.Query("status"), routerCtx.Query("severity"))
	if exportErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "导出告警失败"})
		return
	}

	routerCtx.Header("Content-Disposition", `attachment; filename="a3-alerts.csv"`)
	routerCtx.Data(http.StatusOK, "text/csv; charset=utf-8", buildAlertsCSV(alertList))
}

// alertToJSON 转换告警行模型为对外 JSON。
func alertToJSON(alertRow store.Alert) gin.H {
	item := gin.H{
		"id":          alertRow.ID,
		"device_id":   alertRow.DeviceID,
		"session_key": alertRow.SessionKey,
		"event_id":    alertRow.EventID,
		"rule_id":     alertRow.RuleID,
		"rule_name":   alertRow.RuleName,
		"severity":    alertRow.Severity,
		"action":      alertRow.Action,
		"snippet":     alertRow.Snippet,
		"summary":     alertRow.Summary,
		"status":      alertRow.Status,
		"created_at":  alertRow.CreatedAt,
	}
	if alertRow.AcknowledgedAt != nil {
		item["acknowledged_at"] = alertRow.AcknowledgedAt
	}
	return item
}
