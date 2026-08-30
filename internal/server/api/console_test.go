package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/codingway-hub/a3/internal/server/alert"
	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/internal/servetest"
	"github.com/codingway-hub/a3/pkg/schema"
)

// fixture 汇集一次控制台测试所需的全部依赖。
type fixture struct {
	engine       *gin.Engine
	eventStore   *store.Store
	alertService *alert.Service
	jwtToken     string
}

const (
	fixtureAdminUser     = "admin"
	fixtureAdminPassword = "unit-test-password"
	fixtureJWTSecret     = "unit-jwt-secret"
)

func newFixture(t *testing.T) *fixture {
	t.Helper()
	gin.SetMode(gin.TestMode)

	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts", "sessions", "events", "devices")
	eventStore := store.NewStore(testPool)
	alertService := alert.NewService(eventStore)
	require.NoError(t, alertService.ReloadRules(context.Background()))

	adminPasswordHash, hashErr := bcrypt.GenerateFromPassword([]byte(fixtureAdminPassword), bcrypt.MinCost)
	require.NoError(t, hashErr)

	apiRouter := NewRouter(eventStore, alertService, RouterConfig{
		JWTSecret:         fixtureJWTSecret,
		AdminUsername:     fixtureAdminUser,
		AdminPasswordHash: string(adminPasswordHash),
	})
	return &fixture{
		engine:       apiRouter.Setup(),
		eventStore:   eventStore,
		alertService: alertService,
	}
}

// login 走真实登录接口换取 JWT，供受保护接口使用。
func (test *fixture) login(t *testing.T) {
	t.Helper()
	recorder := test.do(http.MethodPost, "/api/v1/auth/login",
		`{"username":"`+fixtureAdminUser+`","password":"`+fixtureAdminPassword+`"}`, "")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	var loginResponse struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &loginResponse))
	test.jwtToken = loginResponse.Token
}

// do 发起 JSON 请求；bearerToken 为空则不带 Authorization 头。
func (test *fixture) do(method string, target string, jsonBody string, bearerToken string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	var bodyReader io.Reader
	if jsonBody != "" {
		bodyReader = strings.NewReader(jsonBody)
	}
	request := httptest.NewRequest(method, target, bodyReader)
	request.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	test.engine.ServeHTTP(recorder, request)
	return recorder
}

func seedSessionWithEvents(t *testing.T, eventStore *store.Store) {
	t.Helper()
	ctx := context.Background()
	servetest.MustSeedDevice(t, eventStore, "dev-api-1")
	require.NoError(t, eventStore.UpsertSession(ctx, store.SessionUpdate{
		DeviceID: "dev-api-1", SessionKey: "sess-risky", AgentType: schema.AgentTypeClaudeCode,
		Title: "清理生产数据", LastOccurredAt: time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		EventCountDelta: 5, RiskCountDelta: 2,
	}))
	require.NoError(t, eventStore.UpsertSession(ctx, store.SessionUpdate{
		DeviceID: "dev-api-1", SessionKey: "sess-calm", AgentType: schema.AgentTypeClaudeCode,
		Title: "日常开发", LastOccurredAt: time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC),
		EventCountDelta: 3,
	}))
	_, insertErr := eventStore.InsertEvents(ctx, []store.EventRow{{
		EventID: "evt-api-1", DeviceID: "dev-api-1", SessionKey: "sess-risky",
		AgentType: schema.AgentTypeClaudeCode, EventType: schema.EventTypeConversation, Role: "user",
		OccurredAt:  time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
		PayloadJSON: []byte(`{"event_id":"evt-api-1","content":"删除数据"}`), RiskTagsJSON: []byte(`[{"code":"cmd.rm_rf_root"}]`),
	}})
	require.NoError(t, insertErr)
	createAlertErr := eventStore.CreateAlert(ctx, &store.Alert{
		DeviceID: "dev-api-1", SessionKey: "sess-risky", EventID: "evt-api-1",
		RuleID: "cmd.rm_rf_root", RuleName: "高危递归强删(rm -rf 根/家目录)",
		Severity: "high", Action: "block", Snippet: "片段", Summary: "摘要一句话",
	})
	require.NoError(t, createAlertErr)
}

func TestAuthFlow(t *testing.T) {
	test := newFixture(t)

	// 错误口令
	wrongRecorder := test.do(http.MethodPost, "/api/v1/auth/login",
		`{"username":"admin","password":"wrong"}`, "")
	assert.Equal(t, http.StatusUnauthorized, wrongRecorder.Code)

	// 正确口令拿到 Token 后可访问 me
	test.login(t)
	meRecorder := test.do(http.MethodGet, "/api/v1/auth/me", "", test.jwtToken)
	require.Equal(t, http.StatusOK, meRecorder.Code)
	assert.Contains(t, meRecorder.Body.String(), fixtureAdminUser)

	// 无 Token 访问受保护接口
	noAuthRecorder := test.do(http.MethodGet, "/api/v1/stats/overview", "", "")
	assert.Equal(t, http.StatusUnauthorized, noAuthRecorder.Code)
}

func TestStatsOverviewEndpoint(t *testing.T) {
	test := newFixture(t)
	seedSessionWithEvents(t, test.eventStore)
	test.login(t)

	recorder := test.do(http.MethodGet, "/api/v1/stats/overview", "", test.jwtToken)
	require.Equal(t, http.StatusOK, recorder.Code)
	var overview map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &overview))
	assert.Equal(t, float64(2), overview["total_sessions"])
	assert.Equal(t, float64(1), overview["risky_sessions"])
	assert.Equal(t, float64(1), overview["open_alert_count"])
	assert.GreaterOrEqual(t, overview["today_event_count"], float64(0))
	assert.Equal(t, float64(1), overview["active_device_count"], "刚种入的设备应判定在线")
}

func TestSessionsEndpoints(t *testing.T) {
	test := newFixture(t)
	seedSessionWithEvents(t, test.eventStore)
	test.login(t)

	// 列表 + risk_only 过滤
	filtered := test.do(http.MethodGet, "/api/v1/sessions?risk_only=true&page=1&page_size=10", "", test.jwtToken)
	require.Equal(t, http.StatusOK, filtered.Code)
	var listResponse struct {
		Items []struct {
			SessionKey string `json:"session_key"`
			RiskCount  int    `json:"risk_count"`
			Title      string `json:"title"`
			Hostname   string `json:"hostname"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(filtered.Body.Bytes(), &listResponse))
	assert.Equal(t, 1, listResponse.Total)
	assert.Equal(t, "sess-risky", listResponse.Items[0].SessionKey)
	assert.Equal(t, "清理生产数据", listResponse.Items[0].Title)
	assert.Equal(t, "host-dev-api-1", listResponse.Items[0].Hostname)

	// 回放流
	replay := test.do(http.MethodGet, "/api/v1/sessions/dev-api-1/sess-risky/events", "", test.jwtToken)
	require.Equal(t, http.StatusOK, replay.Code)
	assert.Contains(t, replay.Body.String(), "evt-api-1")

	// 回放流 404
	missingReplay := test.do(http.MethodGet, "/api/v1/sessions/dev-api-1/sess-none/events", "", test.jwtToken)
	assert.Equal(t, http.StatusNotFound, missingReplay.Code)

	// JSONL 导出
	exported := test.do(http.MethodGet, "/api/v1/sessions/dev-api-1/sess-risky/export", "", test.jwtToken)
	require.Equal(t, http.StatusOK, exported.Code)
	assert.Contains(t, exported.Header().Get("Content-Disposition"), ".jsonl")
	assert.True(t, strings.HasSuffix(strings.TrimSpace(exported.Body.String()), `}`), "JSONL 每行一个 JSON")
}

func TestAlertsEndpointsAndCSVExport(t *testing.T) {
	test := newFixture(t)
	seedSessionWithEvents(t, test.eventStore)
	test.login(t)

	listed := test.do(http.MethodGet, "/api/v1/alerts?status=open&severity=high", "", test.jwtToken)
	require.Equal(t, http.StatusOK, listed.Code)
	var listResponse struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &listResponse))
	require.Equal(t, 1, listResponse.Total)

	// 确认告警（幂等）
	patchTarget := "/api/v1/alerts/" + listResponse.Items[0].ID
	firstAck := test.do(http.MethodPatch, patchTarget, `{"status":"acknowledged"}`, test.jwtToken)
	assert.Equal(t, http.StatusOK, firstAck.Code)
	secondAck := test.do(http.MethodPatch, patchTarget, `{"status":"acknowledged"}`, test.jwtToken)
	assert.Equal(t, http.StatusOK, secondAck.Code, "重复确认幂等成功")
	missingAck := test.do(http.MethodPatch, "/api/v1/alerts/00000000-0000-0000-0000-00000000dead",
		`{"status":"acknowledged"}`, test.jwtToken)
	assert.Equal(t, http.StatusNotFound, missingAck.Code)

	// CSV 导出：表头与一行数据
	exported := test.do(http.MethodGet, "/api/v1/alerts/export", "", test.jwtToken)
	require.Equal(t, http.StatusOK, exported.Code)
	csvBody := exported.Body.String()
	assert.Contains(t, csvBody, "id,created_at,severity,rule_id,rule_name,device_id,session_key,status,summary")
	assert.Contains(t, csvBody, "cmd.rm_rf_root")
}

func TestDevicesAndRulesEndpoints(t *testing.T) {
	test := newFixture(t)
	seedSessionWithEvents(t, test.eventStore) // 已种 dev-api-1
	test.login(t)

	devices := test.do(http.MethodGet, "/api/v1/devices", "", test.jwtToken)
	require.Equal(t, http.StatusOK, devices.Code)
	assert.Contains(t, devices.Body.String(), `"online":true`, "刚种入的设备心跳为现在，应判定在线")
	assert.Contains(t, devices.Body.String(), "dev-api-1")

	// 规则列表：14 条种子
	rules := test.do(http.MethodGet, "/api/v1/rules", "", test.jwtToken)
	require.Equal(t, http.StatusOK, rules.Code)
	var rulesResponse struct {
		Items []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rules.Body.Bytes(), &rulesResponse))
	assert.Len(t, rulesResponse.Items, 14)

	// 启停 dlp.jwt 并验证引擎热更新
	patched := test.do(http.MethodPatch, "/api/v1/rules/dlp.jwt", `{"enabled":false}`, test.jwtToken)
	require.Equal(t, http.StatusOK, patched.Code)
	missingRule := test.do(http.MethodPatch, "/api/v1/rules/no-such-rule", `{"enabled":true}`, test.jwtToken)
	assert.Equal(t, http.StatusNotFound, missingRule.Code)

	jwtEvent := schema.Event{EventID: "evt-x", EventType: schema.EventTypeConversation, Role: "user",
		Content: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlMzQ1"}
	require.NoError(t, test.alertService.ReloadRules(context.Background()))
	assert.Empty(t, test.alertService.Evaluate(jwtEvent), "停用后引擎不应命中")

	// 恢复启用状态，避免污染其他用例的种子断言
	require.NoError(t, test.eventStore.SetRuleEnabled(context.Background(), "dlp.jwt", true, "api-tester"))

	// 自定义规则全生命周期走 API：每个变更端点各落一条操作留痕，操作者为登录管理员
	customAuditRuleID := "custom.api-audit"
	t.Cleanup(func() {
		cleanupPool, poolErr := pgxpool.New(context.Background(), servetest.TestDatabaseURL(t))
		if poolErr == nil {
			defer cleanupPool.Close()
			_, _ = cleanupPool.Exec(context.Background(), `DELETE FROM rules WHERE id = $1`, customAuditRuleID)
			_, _ = cleanupPool.Exec(context.Background(),
				`DELETE FROM audit_log WHERE target_type='rule' AND target_id=$1`, customAuditRuleID)
		}
	})
	created := test.do(http.MethodPost, "/api/v1/rules", `{
		"id":"custom.api-audit","name":"API 审计规则","category":"test",
		"matcher":{"target":"command","patterns":["terraform\\s+destroy"],"path_globs":[]},
		"severity":"medium","action":"alert","enabled":true}`, test.jwtToken)
	require.Equal(t, http.StatusCreated, created.Code)

	updated := test.do(http.MethodPut, "/api/v1/rules/custom.api-audit", `{
		"id":"custom.api-audit","name":"改名后","category":"test",
		"matcher":{"target":"command","patterns":["terraform\\s+destroy"],"path_globs":[]},
		"severity":"high","action":"alert","enabled":true}`, test.jwtToken)
	require.Equal(t, http.StatusOK, updated.Code)

	deleted := test.do(http.MethodDelete, "/api/v1/rules/custom.api-audit", "", test.jwtToken)
	require.Equal(t, http.StatusOK, deleted.Code)

	ruleAuditListed := test.do(http.MethodGet,
		"/api/v1/audit-log?target_type=rule&target_id=custom.api-audit", "", test.jwtToken)
	require.Equal(t, http.StatusOK, ruleAuditListed.Code)
	var ruleAuditResponse struct {
		Items []struct {
			Action   string `json:"action"`
			Operator string `json:"operator"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(ruleAuditListed.Body.Bytes(), &ruleAuditResponse))
	require.Equal(t, 3, ruleAuditResponse.Total, "创建/更新/删除各留痕一条")
	assert.Equal(t, "rule_delete", ruleAuditResponse.Items[0].Action)
	assert.Equal(t, "rule_update", ruleAuditResponse.Items[1].Action)
	assert.Equal(t, "rule_create", ruleAuditResponse.Items[2].Action)
	for _, auditItem := range ruleAuditResponse.Items {
		assert.Equal(t, fixtureAdminUser, auditItem.Operator)
	}
}

// TestDeviceStatusPatchRevokeAndRestore 控制台吊销/恢复设备闭环。
func TestDeviceStatusPatchRevokeAndRestore(t *testing.T) {
	test := newFixture(t)
	seedSessionWithEvents(t, test.eventStore) // 已种 dev-api-1
	test.login(t)

	// 非法状态拒绝
	badStatus := test.do(http.MethodPatch, "/api/v1/devices/dev-api-1",
		`{"status":"purged"}`, test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, badStatus.Code)

	// 吊销
	revoked := test.do(http.MethodPatch, "/api/v1/devices/dev-api-1",
		`{"status":"revoked"}`, test.jwtToken)
	require.Equal(t, http.StatusOK, revoked.Code)
	assert.Contains(t, revoked.Body.String(), `"status":"revoked"`)

	deviceRow, lookupErr := test.eventStore.GetDeviceByTokenHash(context.Background(), "hash-dev-api-1")
	require.NoError(t, lookupErr, "吊销只改状态，设备行不可丢失")
	assert.Equal(t, "revoked", deviceRow.Status)

	// 列表中可见吊销状态，且审计回放数据不受影响（会话仍在）
	devices := test.do(http.MethodGet, "/api/v1/devices", "", test.jwtToken)
	require.Equal(t, http.StatusOK, devices.Code)
	assert.Contains(t, devices.Body.String(), `"status":"revoked"`)

	// 恢复 active
	restored := test.do(http.MethodPatch, "/api/v1/devices/dev-api-1",
		`{"status":"active"}`, test.jwtToken)
	require.Equal(t, http.StatusOK, restored.Code)
	devicesAfter := test.do(http.MethodGet, "/api/v1/devices", "", test.jwtToken)
	assert.Contains(t, devicesAfter.Body.String(), `"status":"active"`)

	// 设备不存在 → 404
	missing := test.do(http.MethodPatch, "/api/v1/devices/dev-no-such",
		`{"status":"revoked"}`, test.jwtToken)
	assert.Equal(t, http.StatusNotFound, missing.Code)

	// 操作级留痕：吊销与恢复各落一条 device_revoke/device_restore，操作者为登录管理员
	revokedRecorder := test.do(http.MethodPatch, "/api/v1/devices/dev-api-1",
		`{"status":"revoked"}`, test.jwtToken)
	require.Equal(t, http.StatusOK, revokedRecorder.Code)
	auditListed := test.do(http.MethodGet,
		"/api/v1/audit-log?target_type=device&target_id=dev-api-1", "", test.jwtToken)
	require.Equal(t, http.StatusOK, auditListed.Code)
	var auditResponse struct {
		Items []struct {
			Action      string          `json:"action"`
			TargetType  string          `json:"target_type"`
			TargetID    string          `json:"target_id"`
			Operator    string          `json:"operator"`
			Before      json.RawMessage `json:"before"`
			After       json.RawMessage `json:"after"`
			ActionLabel string          `json:"action_label"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(auditListed.Body.Bytes(), &auditResponse))
	require.GreaterOrEqual(t, auditResponse.Total, 3, "恢复+吊销+本次吊销应至少三条留痕")
	assert.Equal(t, "device_revoke", auditResponse.Items[0].Action, "id 倒序：最新在前")
	assert.Equal(t, fixtureAdminUser, auditResponse.Items[0].Operator)
	assert.Equal(t, "dev-api-1", auditResponse.Items[0].TargetID)
	assert.Contains(t, string(auditResponse.Items[0].After), `"status":"revoked"`)
	assert.Equal(t, "吊销设备", auditResponse.Items[0].ActionLabel)

	// 未登录访问审计日志 → 401
	unauthorizedAudit := test.do(http.MethodGet, "/api/v1/audit-log", "", "")
	assert.Equal(t, http.StatusUnauthorized, unauthorizedAudit.Code)
}

// TestAlertsExportNotClampedByListPagination 守护导出数据完整性：
// 列表接口钳制 pageSize≤100，导出必须全量返回（回归 I-1）。
func TestAlertsExportNotClampedByListPagination(t *testing.T) {
	test := newFixture(t)
	test.login(t)

	const seededAlertTotal = 105
	for alertIndex := 0; alertIndex < seededAlertTotal; alertIndex++ {
		require.NoError(t, test.eventStore.CreateAlert(context.Background(), &store.Alert{
			DeviceID:   "dev-export",
			SessionKey: fmt.Sprintf("sess-%03d", alertIndex),
			RuleID:     "cmd.rm_rf_root",
			RuleName:   "高危递归强删(rm -rf 根/家目录)",
			Severity:   "high",
			Action:     "block",
			Summary:    fmt.Sprintf("导出演练告警 %03d", alertIndex),
		}))
	}

	// 列表接口按钳制后的 pageSize 返回（≤100），total 反映真实总数
	listed := test.do(http.MethodGet, "/api/v1/alerts?page_size=100", "", test.jwtToken)
	require.Equal(t, http.StatusOK, listed.Code)
	var listResponse struct {
		Items []json.RawMessage `json:"items"`
		Total int               `json:"total"`
	}
	require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &listResponse))
	assert.Len(t, listResponse.Items, 100)
	assert.Equal(t, seededAlertTotal, listResponse.Total)

	// 导出必须全量：105 行数据 + 1 行表头（回归 I-1 静默截断）
	exported := test.do(http.MethodGet, "/api/v1/alerts/export", "", test.jwtToken)
	require.Equal(t, http.StatusOK, exported.Code)
	exportedLineCount := strings.Count(strings.TrimRight(exported.Body.String(), "\n"), "\n") + 1
	assert.Equal(t, seededAlertTotal+1, exportedLineCount)
}

// TestAlertsCSVFormulaPrefixNeutralized summary 以公式前缀字符开头时须被中和，防 Excel/WPS 公式注入。
func TestAlertsCSVFormulaPrefixNeutralized(t *testing.T) {
	exportedCSV := string(buildAlertsCSV([]store.Alert{{Summary: "=HYPERLINK(\"http://evil\",\"x\")"}}))
	assert.Contains(t, exportedCSV, "'=HYPERLINK")

	benignCSV := string(buildAlertsCSV([]store.Alert{{Summary: "普通告警摘要"}}))
	assert.Contains(t, benignCSV, "普通告警摘要", "普通文本不应被改写")
}

// TestRulesCRUDEndpoints 规则中心管理 API 全流程：
// 创建（含 409/400 拒绝）→ 更新 → builtin 守护 → 软删 → 列表消失。
func TestRulesCRUDEndpoints(t *testing.T) {
	test := newFixture(t)
	test.login(t)
	customRuleID := "custom.api-rule"
	t.Cleanup(func() {
		cleanupPool, poolErr := pgxpool.New(context.Background(), servetest.TestDatabaseURL(t))
		if poolErr == nil {
			defer cleanupPool.Close()
			_, _ = cleanupPool.Exec(context.Background(), `DELETE FROM rules WHERE id = $1`, customRuleID)
		}
	})

	createBody := `{"id":"` + customRuleID + `","name":"API 测试规则","category":"test",` +
		`"matcher":{"target":"command","patterns":["curl .*evil"],"path_globs":[]},` +
		`"severity":"medium","action":"alert","enabled":true}`
	recorder := test.do(http.MethodPost, "/api/v1/rules", createBody, test.jwtToken)
	require.Equal(t, http.StatusCreated, recorder.Code, recorder.Body.String())

	duplicateRecorder := test.do(http.MethodPost, "/api/v1/rules", createBody, test.jwtToken)
	assert.Equal(t, http.StatusConflict, duplicateRecorder.Code)

	badRegexRecorder := test.do(http.MethodPost, "/api/v1/rules",
		`{"id":"custom.bad-regex","name":"坏正则","category":"test",`+
			`"matcher":{"target":"command","patterns":["([unclosed"],"path_globs":[]},`+
			`"severity":"low","action":"alert","enabled":true}`, test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, badRegexRecorder.Code)

	badIDRecorder := test.do(http.MethodPost, "/api/v1/rules",
		`{"id":"Bad ID!","name":"坏ID","category":"test",`+
			`"matcher":{"target":"command","patterns":["x"],"path_globs":[]},`+
			`"severity":"low","action":"alert","enabled":true}`, test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, badIDRecorder.Code)

	updateBody := `{"name":"改名后规则","category":"test",` +
		`"matcher":{"target":"command","patterns":["curl .*evil"],"path_globs":[]},` +
		`"severity":"high","action":"block","enabled":true}`
	updateRecorder := test.do(http.MethodPut, "/api/v1/rules/"+customRuleID, updateBody, test.jwtToken)
	require.Equal(t, http.StatusOK, updateRecorder.Code, updateRecorder.Body.String())
	listRecorder := test.do(http.MethodGet, "/api/v1/rules", "", test.jwtToken)
	require.Equal(t, http.StatusOK, listRecorder.Code)
	assert.Contains(t, listRecorder.Body.String(), "改名后规则")

	putBuiltinRecorder := test.do(http.MethodPut, "/api/v1/rules/dlp.jwt", updateBody, test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, putBuiltinRecorder.Code, "builtin 内容不可改")
	deleteBuiltinRecorder := test.do(http.MethodDelete, "/api/v1/rules/dlp.jwt", "", test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, deleteBuiltinRecorder.Code, "builtin 不可删")

	deleteRecorder := test.do(http.MethodDelete, "/api/v1/rules/"+customRuleID, "", test.jwtToken)
	require.Equal(t, http.StatusOK, deleteRecorder.Code, deleteRecorder.Body.String())
	repeatDeleteRecorder := test.do(http.MethodDelete, "/api/v1/rules/"+customRuleID, "", test.jwtToken)
	assert.Equal(t, http.StatusNotFound, repeatDeleteRecorder.Code, "软删后重复删除应 404")
}
