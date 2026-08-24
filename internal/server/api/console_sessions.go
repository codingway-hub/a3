package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/store"
)

// sessionJSON 是会话列表/详情的对外形状（snake_case）。
type sessionJSON struct {
	DeviceID   string    `json:"device_id"`
	Hostname   string    `json:"hostname"`
	SessionKey string    `json:"session_key"`
	AgentType  string    `json:"agent_type"`
	Title      string    `json:"title"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at"`
	EventCount int       `json:"event_count"`
	RiskCount  int       `json:"risk_count"`
}

func toSessionJSON(sessionRow store.Session) sessionJSON {
	return sessionJSON{
		DeviceID:   sessionRow.DeviceID,
		Hostname:   sessionRow.Hostname,
		SessionKey: sessionRow.SessionKey,
		AgentType:  sessionRow.AgentType,
		Title:      sessionRow.Title,
		StartedAt:  sessionRow.StartedAt,
		EndedAt:    sessionRow.EndedAt,
		EventCount: sessionRow.EventCount,
		RiskCount:  sessionRow.RiskCount,
	}
}

// HandleListSessions GET /sessions?keyword=&device_id=&risk_only=&started_from=&started_to=&page=&page_size=
func (api *Router) HandleListSessions(routerCtx *gin.Context) {
	sessionFilter := store.SessionFilter{
		Keyword:  routerCtx.Query("keyword"),
		DeviceID: routerCtx.Query("device_id"),
		RiskOnly: routerCtx.Query("risk_only") == "true",
	}
	if startedFrom, hasFrom := parseTimeQuery(routerCtx, "started_from"); hasFrom {
		sessionFilter.StartedFrom = &startedFrom
	}
	if startedTo, hasTo := parseTimeQuery(routerCtx, "started_to"); hasTo {
		sessionFilter.StartedTo = &startedTo
	}
	sessionFilter.Page = parsePositiveIntQuery(routerCtx, "page", 1)
	sessionFilter.PageSize = parsePositiveIntQuery(routerCtx, "page_size", 20)

	sessionList, totalCount, listErr := api.eventStore.ListSessions(routerCtx.Request.Context(), sessionFilter)
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询会话失败"})
		return
	}

	items := make([]sessionJSON, 0, len(sessionList))
	for _, sessionRow := range sessionList {
		items = append(items, toSessionJSON(sessionRow))
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items, "total": totalCount})
}

// HandleSessionEvents GET /sessions/:deviceId/:sessionKey/events —— 会话回放流。
func (api *Router) HandleSessionEvents(routerCtx *gin.Context) {
	eventRows, listErr := api.eventStore.ListEventsBySession(routerCtx.Request.Context(),
		routerCtx.Param("deviceId"), routerCtx.Param("sessionKey"))
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询会话事件失败"})
		return
	}
	if len(eventRows) == 0 {
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "会话不存在"})
		return
	}

	items := make([]gin.H, 0, len(eventRows))
	for _, eventRow := range eventRows {
		var payload any
		_ = jsonUnmarshalStrict(eventRow.PayloadJSON, &payload)
		var riskTags any
		_ = jsonUnmarshalStrict(eventRow.RiskTagsJSON, &riskTags)
		items = append(items, gin.H{
			"event_id":    eventRow.EventID,
			"event_type":  eventRow.EventType,
			"role":        eventRow.Role,
			"occurred_at": eventRow.OccurredAt,
			"payload":     payload,
			"risk_tags":   riskTags,
		})
	}
	routerCtx.JSON(http.StatusOK, gin.H{"items": items})
}

// HandleSessionExport GET /sessions/:deviceId/:sessionKey/export —— JSONL 下载。
func (api *Router) HandleSessionExport(routerCtx *gin.Context) {
	deviceParam := routerCtx.Param("deviceId")
	sessionParam := routerCtx.Param("sessionKey")
	eventRows, listErr := api.eventStore.ListEventsBySession(routerCtx.Request.Context(),
		deviceParam, sessionParam)
	if listErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "导出会话失败"})
		return
	}

	exportFilename := fmt.Sprintf("a3-session-%s-%s.jsonl", deviceParam, sessionParam)
	routerCtx.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, exportFilename))
	routerCtx.Header("Content-Type", "application/x-ndjson; charset=utf-8")
	routerCtx.Status(http.StatusOK)
	for _, eventRow := range eventRows {
		_, _ = routerCtx.Writer.Write(append(eventRow.PayloadJSON, '\n'))
	}
}

// parseTimeQuery 解析 RFC3339 时间查询参数；缺失返回 (零值,false)，非法值忽略按不过滤处理。
func parseTimeQuery(routerCtx *gin.Context, name string) (time.Time, bool) {
	rawValue := routerCtx.Query(name)
	if rawValue == "" {
		return time.Time{}, false
	}
	parsedValue, parseErr := time.Parse(time.RFC3339, rawValue)
	if parseErr != nil {
		return time.Time{}, false
	}
	return parsedValue, true
}

// parsePositiveIntQuery 解析正整数查询参数，非法或缺失时返回默认值。
func parsePositiveIntQuery(routerCtx *gin.Context, name string, defaultValue int) int {
	rawValue := routerCtx.Query(name)
	if rawValue == "" {
		return defaultValue
	}
	parsedValue, parseErr := strconv.Atoi(rawValue)
	if parseErr != nil || parsedValue < 1 {
		return defaultValue
	}
	return parsedValue
}
