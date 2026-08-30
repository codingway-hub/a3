package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/rules"
	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/pkg/schema"
)

// auditOperator 从 JWT 上下文取操作者；缺失时落 "unknown"（fail-open：留痕优先于阻断变更）。
func auditOperator(routerCtx *gin.Context) string {
	if username, hasUsername := auth.UsernameFrom(routerCtx); hasUsername && username != "" {
		return username
	}
	return "unknown"
}

// ruleIDPattern 自定义规则 id 约束：小写字母/数字/下划线/点/连字符，3-64 字符。
// （与终端规则快照、告警关联展示共用同一命名空间，禁止大小写歧义。）
var ruleIDPattern = regexp.MustCompile(`^[a-z0-9_.-]{3,64}$`)

// ruleUpsertRequest 创建/更新规则请求体；matcher 直接采用存储形状
// （target/patterns/path_globs），序列化后即 rules.matcher jsonb 原文。
type ruleUpsertRequest struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Matcher  struct {
		Target    string   `json:"target"`
		Patterns  []string `json:"patterns"`
		PathGlobs []string `json:"path_globs"`
	} `json:"matcher"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
}

// toBusinessRule 请求体 → 规则业务对象（供 rules.Validate 校验）。
func (upsertRequest *ruleUpsertRequest) toBusinessRule(ruleID string) rules.Rule {
	return rules.Rule{
		ID:        ruleID,
		Name:      upsertRequest.Name,
		Category:  upsertRequest.Category,
		Target:    upsertRequest.Matcher.Target,
		Patterns:  upsertRequest.Matcher.Patterns,
		PathGlobs: upsertRequest.Matcher.PathGlobs,
		Severity:  schema.Severity(upsertRequest.Severity),
		Action:    schema.RiskAction(upsertRequest.Action),
		Enabled:   upsertRequest.Enabled,
	}
}

// HandleListRules GET /rules —— 规则全集（含停用，不含已删除）。
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

// HandleCreateRule POST /rules —— 新建自定义规则并热更新扫描引擎。
func (api *Router) HandleCreateRule(routerCtx *gin.Context) {
	var upsertRequest ruleUpsertRequest
	if bindErr := routerCtx.ShouldBindJSON(&upsertRequest); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}
	if !ruleIDPattern.MatchString(upsertRequest.ID) {
		routerCtx.JSON(http.StatusBadRequest, gin.H{
			"error": "id 需为 3-64 位小写字母/数字/下划线/点/连字符"})
		return
	}
	ctx := routerCtx.Request.Context()

	if validateErr := rules.Validate(upsertRequest.toBusinessRule(upsertRequest.ID)); validateErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": validateErr.Error()})
		return
	}
	matcherBytes, marshalErr := json.Marshal(upsertRequest.Matcher)
	if marshalErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "matcher 序列化失败"})
		return
	}
	ruleRecord := &store.RuleRecord{
		ID: upsertRequest.ID, Name: upsertRequest.Name, Category: upsertRequest.Category,
		Matcher: matcherBytes, Severity: upsertRequest.Severity, Action: upsertRequest.Action,
		Enabled: upsertRequest.Enabled, Builtin: false,
	}
	switch createErr := api.eventStore.CreateRule(ctx, ruleRecord, auditOperator(routerCtx)); {
	case createErr == nil:
	case errors.Is(createErr, store.ErrAlreadyExists):
		routerCtx.JSON(http.StatusConflict, gin.H{"error": "规则 ID 已存在"})
		return
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "创建规则失败"})
		return
	}

	// 与启停一致：变更成功后立即重载扫描引擎，保证策略即时生效
	if reloadErr := api.alertService.ReloadRules(ctx); reloadErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "规则已创建但扫描引擎重载失败"})
		return
	}
	routerCtx.JSON(http.StatusCreated, gin.H{"id": ruleRecord.ID, "created_at": ruleRecord.CreatedAt})
}

// HandleUpdateRule PUT /rules/:ruleID —— 全量更新自定义规则内容（builtin 仅允许启停）。
func (api *Router) HandleUpdateRule(routerCtx *gin.Context) {
	ruleID := routerCtx.Param("ruleID")
	var upsertRequest ruleUpsertRequest
	if bindErr := routerCtx.ShouldBindJSON(&upsertRequest); bindErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "请求体不是合法 JSON"})
		return
	}
	ctx := routerCtx.Request.Context()

	if validateErr := rules.Validate(upsertRequest.toBusinessRule(ruleID)); validateErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": validateErr.Error()})
		return
	}
	existingRecord, getErr := api.eventStore.GetRule(ctx, ruleID)
	switch {
	case getErr == nil:
	case errors.Is(getErr, store.ErrNotFound):
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询规则失败"})
		return
	}
	if existingRecord.Builtin {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "内置规则内容随版本维护，仅允许启停"})
		return
	}

	matcherBytes, marshalErr := json.Marshal(upsertRequest.Matcher)
	if marshalErr != nil {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "matcher 序列化失败"})
		return
	}
	updateErr := api.eventStore.UpdateRule(ctx, &store.RuleRecord{
		ID: ruleID, Name: upsertRequest.Name, Category: upsertRequest.Category,
		Matcher: matcherBytes, Severity: upsertRequest.Severity, Action: upsertRequest.Action,
		Enabled: upsertRequest.Enabled,
	}, auditOperator(routerCtx))
	switch {
	case updateErr == nil:
	case errors.Is(updateErr, store.ErrNotFound):
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "规则不存在或已删除"})
		return
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "更新规则失败"})
		return
	}

	if reloadErr := api.alertService.ReloadRules(ctx); reloadErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "规则已更新但扫描引擎重载失败"})
		return
	}
	routerCtx.JSON(http.StatusOK, gin.H{"id": ruleID})
}

// HandleDeleteRule DELETE /rules/:ruleID —— 软删自定义规则（builtin 不可删）。
func (api *Router) HandleDeleteRule(routerCtx *gin.Context) {
	ruleID := routerCtx.Param("ruleID")
	ctx := routerCtx.Request.Context()

	existingRecord, getErr := api.eventStore.GetRule(ctx, ruleID)
	switch {
	case getErr == nil:
	case errors.Is(getErr, store.ErrNotFound):
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "查询规则失败"})
		return
	}
	if existingRecord.Builtin {
		routerCtx.JSON(http.StatusBadRequest, gin.H{"error": "内置规则不允许删除，仅允许启停"})
		return
	}

	switch deleteErr := api.eventStore.DeleteRule(ctx, ruleID, auditOperator(routerCtx)); {
	case deleteErr == nil:
	case errors.Is(deleteErr, store.ErrNotFound):
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "规则不存在或已删除"})
		return
	default:
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "删除规则失败"})
		return
	}

	if reloadErr := api.alertService.ReloadRules(ctx); reloadErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "规则已删除但扫描引擎重载失败"})
		return
	}
	routerCtx.JSON(http.StatusOK, gin.H{"id": ruleID, "deleted": true})
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

	patchErr := api.eventStore.SetRuleEnabled(ctx, routerCtx.Param("ruleID"),
		*patchRequest.Enabled, auditOperator(routerCtx))
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
