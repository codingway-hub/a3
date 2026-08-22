package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(filtered.Body.Bytes(), &listResponse))
	assert.Equal(t, 1, listResponse.Total)
	assert.Equal(t, "sess-risky", listResponse.Items[0].SessionKey)
	assert.Equal(t, "清理生产数据", listResponse.Items[0].Title)

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
	require.NoError(t, test.eventStore.SetRuleEnabled(context.Background(), "dlp.jwt", true))
}
