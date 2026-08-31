package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/store"
)

// int64String 简化 int64 → 十进制字符串（测试路径参数拼接用）。
func int64String(value int64) string {
	return strconv.FormatInt(value, 10)
}

const auditorUsername = "auditor-a"
const auditorPassword = "auditor-pass-1"

// seedAuditorAlert 造一条 open 告警并返回其 ID（角色矩阵确认告警用例用）。
func seedAuditorAlert(t *testing.T, test *fixture) string {
	t.Helper()
	alertRow := &store.Alert{
		DeviceID: "dev-api-1", SessionKey: "sess-risky", EventID: "evt-api-1",
		RuleID: "cmd.rm_rf_root", RuleName: "高危递归强删", Severity: "high", Action: "block",
		Snippet: "片段", Summary: "摘要",
	}
	require.NoError(t, test.eventStore.CreateAlert(context.Background(), alertRow))
	return alertRow.ID
}

// auditEntriesForUser 查询目标为指定用户名的审计记录数。
func auditEntriesForUser(t *testing.T, test *fixture, action string, targetID string) int {
	t.Helper()
	entries, _, countErr := test.eventStore.ListAuditLog(context.Background(), store.AuditFilter{
		TargetType: store.AuditTargetUser, TargetID: targetID, Page: 1, PageSize: 50,
	})
	require.NoError(t, countErr)
	actionCount := 0
	for _, entry := range entries {
		if entry.Action == action {
			actionCount++
		}
	}
	return actionCount
}

func TestUserManagementByAdmin(t *testing.T) {
	test := newFixture(t)
	test.login(t)

	// 建号：auditor 角色
	createRecorder := test.do(http.MethodPost, "/api/v1/users",
		`{"username":"`+auditorUsername+`","password":"`+auditorPassword+`","role":"auditor"}`, test.jwtToken)
	require.Equal(t, http.StatusCreated, createRecorder.Code, createRecorder.Body.String())
	assert.Equal(t, 1, auditEntriesForUser(t, test, store.AuditActionUserCreate, auditorUsername))

	// 重名 409
	duplicateRecorder := test.do(http.MethodPost, "/api/v1/users",
		`{"username":"`+auditorUsername+`","password":"`+auditorPassword+`","role":"auditor"}`, test.jwtToken)
	assert.Equal(t, http.StatusConflict, duplicateRecorder.Code)

	// 非法角色/短口令/坏用户名 400
	badRoleRecorder := test.do(http.MethodPost, "/api/v1/users",
		`{"username":"someone","password":"long-enough-pw","role":"superuser"}`, test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, badRoleRecorder.Code)
	shortPwRecorder := test.do(http.MethodPost, "/api/v1/users",
		`{"username":"someone","password":"short","role":"auditor"}`, test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, shortPwRecorder.Code)
	badNameRecorder := test.do(http.MethodPost, "/api/v1/users",
		`{"username":"非法*用户名","password":"long-enough-pw","role":"auditor"}`, test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, badNameRecorder.Code)

	// 列表：不回哈希、含新建账号
	listRecorder := test.do(http.MethodGet, "/api/v1/users", "", test.jwtToken)
	require.Equal(t, http.StatusOK, listRecorder.Code)
	assert.NotContains(t, listRecorder.Body.String(), "hash-")
	assert.Contains(t, listRecorder.Body.String(), auditorUsername)

	// 建 auditor 并登录，改角色 → auditor Token 再访问 admin 端点被拒
	auditorToken := test.createUserAndLogin(t, "auditor-b", "auditor-pass-2", "auditor")
	forbiddenListRecorder := test.do(http.MethodGet, "/api/v1/users", "", auditorToken)
	assert.Equal(t, http.StatusForbidden, forbiddenListRecorder.Code)

	// 找到 auditor-b 的 ID 后改角色为 admin
	listRecorder2 := test.do(http.MethodGet, "/api/v1/users", "", test.jwtToken)
	var listResponse struct {
		Items []struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
			Role     string `json:"role"`
			Enabled  bool   `json:"enabled"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(listRecorder2.Body.Bytes(), &listResponse))
	var auditorBID int64
	for _, item := range listResponse.Items {
		if item.Username == "auditor-b" {
			auditorBID = item.ID
		}
	}
	require.NotZero(t, auditorBID)
	patchRecorder := test.do(http.MethodPatch, "/api/v1/users/"+int64String(auditorBID),
		`{"role":"admin"}`, test.jwtToken)
	require.Equal(t, http.StatusOK, patchRecorder.Code, patchRecorder.Body.String())
	assert.Equal(t, 1, auditEntriesForUser(t, test, store.AuditActionUserUpdate, "auditor-b"))

	// 停用 auditor-a：其旧 token 在 TTL 内仍有效（无状态 JWT 已声明限制），重登 401
	var auditorAID int64
	for _, item := range listResponse.Items {
		if item.Username == auditorUsername {
			auditorAID = item.ID
		}
	}
	require.NotZero(t, auditorAID)
	disableRecorder := test.do(http.MethodPatch, "/api/v1/users/"+int64String(auditorAID),
		`{"enabled":false}`, test.jwtToken)
	require.Equal(t, http.StatusOK, disableRecorder.Code)
	reLoginRecorder := test.do(http.MethodPost, "/api/v1/auth/login",
		`{"username":"`+auditorUsername+`","password":"`+auditorPassword+`"}`, "")
	assert.Equal(t, http.StatusUnauthorized, reLoginRecorder.Code)
	assert.Contains(t, reLoginRecorder.Body.String(), "停用")

	// 重置口令 → 重新启用 → 新口令可登录（重置不自动解停，启用是独立操作）
	resetRecorder := test.do(http.MethodPatch, "/api/v1/users/"+int64String(auditorAID)+"/password",
		`{"password":"new-pass-12345"}`, test.jwtToken)
	require.Equal(t, http.StatusOK, resetRecorder.Code, resetRecorder.Body.String())
	assert.Equal(t, 1, auditEntriesForUser(t, test, store.AuditActionUserPasswordReset, auditorUsername))
	stillDisabledRecorder := test.do(http.MethodPost, "/api/v1/auth/login",
		`{"username":"`+auditorUsername+`","password":"new-pass-12345"}`, "")
	assert.Equal(t, http.StatusUnauthorized, stillDisabledRecorder.Code, "停用态重置口令后仍不可登录")

	enableRecorder := test.do(http.MethodPatch, "/api/v1/users/"+int64String(auditorAID),
		`{"enabled":true}`, test.jwtToken)
	require.Equal(t, http.StatusOK, enableRecorder.Code)
	assert.Equal(t, 2, auditEntriesForUser(t, test, store.AuditActionUserUpdate, auditorUsername))

	newLoginRecorder := test.do(http.MethodPost, "/api/v1/auth/login",
		`{"username":"`+auditorUsername+`","password":"new-pass-12345"}`, "")
	assert.Equal(t, http.StatusOK, newLoginRecorder.Code)

	// 不存在的用户 404
	missingRecorder := test.do(http.MethodPatch, "/api/v1/users/99999", `{"enabled":false}`, test.jwtToken)
	assert.Equal(t, http.StatusNotFound, missingRecorder.Code)
}

func TestSelfLockProtection(t *testing.T) {
	test := newFixture(t)
	test.login(t)

	// 当前登录账号是 fixtureAdminUser：找到自己的 ID
	listRecorder := test.do(http.MethodGet, "/api/v1/users", "", test.jwtToken)
	var listResponse struct {
		Items []struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(listRecorder.Body.Bytes(), &listResponse))
	var selfID int64
	for _, item := range listResponse.Items {
		if item.Username == fixtureAdminUser {
			selfID = item.ID
		}
	}
	require.NotZero(t, selfID)

	// 自停 400、自降角色 400（防把自己锁在外面）
	selfDisableRecorder := test.do(http.MethodPatch, "/api/v1/users/"+int64String(selfID),
		`{"enabled":false}`, test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, selfDisableRecorder.Code)
	selfRoleRecorder := test.do(http.MethodPatch, "/api/v1/users/"+int64String(selfID),
		`{"role":"auditor"}`, test.jwtToken)
	assert.Equal(t, http.StatusBadRequest, selfRoleRecorder.Code)
}

func TestAuditorRoleMatrix(t *testing.T) {
	test := newFixture(t)
	test.login(t)
	auditorToken := test.createUserAndLogin(t, auditorUsername, auditorPassword, "auditor")

	// 允许：只读 + 确认告警 + 导出
	assert.Equal(t, http.StatusOK, test.do(http.MethodGet, "/api/v1/rules", "", auditorToken).Code)
	assert.Equal(t, http.StatusOK, test.do(http.MethodGet, "/api/v1/devices", "", auditorToken).Code)
	assert.Equal(t, http.StatusOK, test.do(http.MethodGet, "/api/v1/alerts", "", auditorToken).Code)
	assert.Equal(t, http.StatusOK, test.do(http.MethodGet, "/api/v1/stats/overview", "", auditorToken).Code)
	assert.Equal(t, http.StatusOK, test.do(http.MethodGet, "/api/v1/audit-log", "", auditorToken).Code)
	assert.Equal(t, http.StatusOK, test.do(http.MethodGet, "/api/v1/alerts/export", "", auditorToken).Code)

	alertID := seedAuditorAlert(t, test)
	ackRecorder := test.do(http.MethodPatch, "/api/v1/alerts/"+alertID,
		`{"status":"acknowledged"}`, auditorToken)
	assert.Equal(t, http.StatusOK, ackRecorder.Code, "审计员可确认告警")

	// 拒绝：规则写、设备吊销、用户管理
	assert.Equal(t, http.StatusForbidden, test.do(http.MethodPost, "/api/v1/rules",
		`{"id":"x.y","name":"n","category":"cmd","matcher":{"target":"cmd","patterns":["a"]},"severity":"low","action":"alert","enabled":true}`, auditorToken).Code)
	assert.Equal(t, http.StatusForbidden, test.do(http.MethodPatch, "/api/v1/devices/dev-api-1",
		`{"status":"revoked"}`, auditorToken).Code)
	assert.Equal(t, http.StatusForbidden, test.do(http.MethodGet, "/api/v1/users", "", auditorToken).Code)
	assert.Equal(t, http.StatusForbidden, test.do(http.MethodPost, "/api/v1/users",
		`{"username":"a-b","password":"long-enough-pw","role":"admin"}`, auditorToken).Code)
	assert.Equal(t, http.StatusForbidden, test.do(http.MethodPatch, "/api/v1/users/1/password",
		`{"password":"long-enough-pw"}`, auditorToken).Code)
}
