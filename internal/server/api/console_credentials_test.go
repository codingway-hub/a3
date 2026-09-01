package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/internal/servetest"
)

// createInstallCredentialForTest 走真实端点生成凭据并返回其 ID（封装校验样板）。
func createInstallCredentialForTest(t *testing.T, test *fixture, minutes int, maxUses int, scope string) (int64, string) {
	t.Helper()
	payload := `{"expires_in_minutes":` + int64String(int64(minutes)) +
		`,"max_uses":` + int64String(int64(maxUses)) +
		`,"scope":"` + scope + `"}`
	recorder := test.do(http.MethodPost, "/api/v1/credentials", payload, test.jwtToken)
	require.Equal(t, http.StatusCreated, recorder.Code, recorder.Body.String())
	var created struct {
		ID   int64  `json:"id"`
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &created))
	require.Regexp(t, `^a3i_[0-9a-f]{64}$`, created.Code, "明文代码只在创建响应出现一次")
	return created.ID, created.Code
}

func TestInstallCredentialLifecycleByAdmin(t *testing.T) {
	test := newFixture(t)
	test.login(t)

	credentialID, plainCode := createInstallCredentialForTest(t, test, 60, 3, "device")

	// 列表不含明文代码，仅摘要前缀 + 元数据
	listRecorder := test.do(http.MethodGet, "/api/v1/credentials", "", test.jwtToken)
	require.Equal(t, http.StatusOK, listRecorder.Code)
	var listResponse struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(listRecorder.Body.Bytes(), &listResponse))
	require.Len(t, listResponse.Items, 1)
	item := listResponse.Items[0]
	assert.Equal(t, float64(3), item["max_uses"])
	assert.Equal(t, "device", item["scope"])
	assert.True(t, item["enabled"].(bool))
	assert.Contains(t, listRecorder.Body.String(), "code_hint")
	assert.NotContains(t, listRecorder.Body.String(), plainCode, "列表不得泄露明文代码")

	// 成功使用后：/uses 应回显归属与结果
	useID, outcome, consumeErr := test.eventStore.ConsumeInstallCredential(context.Background(),
		auth.HashToken(plainCode), "10.9.8.7")
	require.NoError(t, consumeErr)
	assert.Equal(t, store.CredentialOutcomeSuccess, outcome)
	require.NoError(t, test.eventStore.SetCredentialUseDeviceID(context.Background(), useID, "dev-uses-1"))

	usesRecorder := test.do(http.MethodGet, "/api/v1/credentials/"+int64String(credentialID)+"/uses", "", test.jwtToken)
	require.Equal(t, http.StatusOK, usesRecorder.Code)
	var usesResponse struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.Unmarshal(usesRecorder.Body.Bytes(), &usesResponse))
	assert.Equal(t, 1, usesResponse.Total)
	assert.Equal(t, "success", usesResponse.Items[0]["outcome"])
	assert.Equal(t, "dev-uses-1", usesResponse.Items[0]["device_id"])

	// 吊销即生效，且可重复吊销请求返回有效结果（接口层对不存在走 404→这里首次吊销 200）
	revokeRecorder := test.do(http.MethodPost, "/api/v1/credentials/"+int64String(credentialID)+"/revoke",
		"", test.jwtToken)
	assert.Equal(t, http.StatusOK, revokeRecorder.Code)
	revokeAgainRecorder := test.do(http.MethodPost, "/api/v1/credentials/"+int64String(credentialID)+"/revoke",
		"", test.jwtToken)
	assert.Equal(t, http.StatusNotFound, revokeAgainRecorder.Code, "重复吊销应 404（幂等不重复留痕）")

	// 审计留痕：创建 + 吊销各一条，目标类型 credential
	assert.Equal(t, 1, auditEntriesForTarget(t, test, store.AuditTargetCredential,
		"credential_create", int64String(credentialID)), "credential_create 留痕一次")
	assert.Equal(t, 1, auditEntriesForTarget(t, test, store.AuditTargetCredential,
		"credential_revoke", int64String(credentialID)), "credential_revoke 留痕一次")
}

func TestInstallCredentialCreateValidation(t *testing.T) {
	test := newFixture(t)
	test.login(t)

	cases := []struct {
		name    string
		payload string
	}{
		{"有效期过短", `{"expires_in_minutes":0,"max_uses":1,"scope":"device"}`},
		{"有效期超长", `{"expires_in_minutes":525601,"max_uses":1,"scope":"device"}`},
		{"用量过小", `{"expires_in_minutes":60,"max_uses":0,"scope":"device"}`},
		{"用量过大", `{"expires_in_minutes":60,"max_uses":10001,"scope":"device"}`},
		{"scope 非法", `{"expires_in_minutes":60,"max_uses":1,"scope":"rule"}`},
		{"请求体非法", `not-json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := test.do(http.MethodPost, "/api/v1/credentials", tc.payload, test.jwtToken)
			assert.Equal(t, http.StatusBadRequest, recorder.Code, recorder.Body.String())
		})
	}
}

func TestInstallCredentialRoleMatrix(t *testing.T) {
	test := newFixture(t)
	auditorToken := test.createUserAndLogin(t, "cred-auditor", "auditor-pass-1", "auditor")

	assert.Equal(t, http.StatusForbidden, test.do(http.MethodGet, "/api/v1/credentials", "", auditorToken).Code)
	assert.Equal(t, http.StatusForbidden,
		test.do(http.MethodPost, "/api/v1/credentials", `{"expires_in_minutes":60,"max_uses":1,"scope":"device"}`, auditorToken).Code)
	assert.Equal(t, http.StatusForbidden,
		test.do(http.MethodPost, "/api/v1/credentials/1/revoke", "", auditorToken).Code)
	assert.Equal(t, http.StatusForbidden,
		test.do(http.MethodGet, "/api/v1/credentials/1/uses", "", auditorToken).Code)

	// 未登录一律 401
	assert.Equal(t, http.StatusUnauthorized, test.do(http.MethodGet, "/api/v1/credentials", "", "").Code)
	assert.Equal(t, http.StatusUnauthorized,
		test.do(http.MethodPost, "/api/v1/credentials", `{}`, "").Code)
}

func TestRotateDeviceTokenByAdmin(t *testing.T) {
	test := newFixture(t)
	test.login(t)
	ctx := context.Background()

	servetest.MustSeedDevice(t, test.eventStore, "dev-rotate-1")
	oldTokenHash := storeTokenHashOf(t, test, "dev-rotate-1")

	rotatedRecorder := test.do(http.MethodPost, "/api/v1/devices/dev-rotate-1/token", "", test.jwtToken)
	require.Equal(t, http.StatusOK, rotatedRecorder.Code, rotatedRecorder.Body.String())
	var response struct {
		DeviceID string `json:"device_id"`
		Token    string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rotatedRecorder.Body.Bytes(), &response))
	require.Regexp(t, `^a3d_[0-9a-f]{64}$`, response.Token, "新 Token 明文仅此一次下发")

	// 旧 Token 立即失效；新 Token 可查得
	_, oldLookupErr := test.eventStore.GetDeviceByTokenHash(ctx, oldTokenHash)
	assert.True(t, errors.Is(oldLookupErr, store.ErrNotFound), "轮换后旧 Token 必须失效")
	newDevice, newLookupErr := test.eventStore.GetDeviceByTokenHash(ctx, auth.HashToken(response.Token))
	require.NoError(t, newLookupErr)
	assert.Equal(t, "dev-rotate-1", newDevice.DeviceID)

	// 审计：device_token_rotate 落一条（设备类目标）
	assert.Equal(t, 1, auditEntriesForTarget(t, test, "device",
		"device_token_rotate", "dev-rotate-1"))

	// 不存在设备 → 404
	missingRecorder := test.do(http.MethodPost, "/api/v1/devices/no-such-device/token", "", test.jwtToken)
	assert.Equal(t, http.StatusNotFound, missingRecorder.Code)
}

func TestRotateDeviceTokenRoleMatrix(t *testing.T) {
	test := newFixture(t)
	servetest.MustSeedDevice(t, test.eventStore, "dev-rotate-matrix")
	auditorToken := test.createUserAndLogin(t, "rotate-auditor", "auditor-pass-1", "auditor")
	assert.Equal(t, http.StatusForbidden,
		test.do(http.MethodPost, "/api/v1/devices/dev-rotate-matrix/token", "", auditorToken).Code)
}

// storeTokenHashOf 读取设备当前 token_hash（断言轮换前基线）。
func storeTokenHashOf(t *testing.T, test *fixture, deviceID string) string {
	t.Helper()
	deviceList, listErr := test.eventStore.ListDevices(context.Background())
	require.NoError(t, listErr)
	for _, device := range deviceList {
		if device.DeviceID == deviceID {
			return device.TokenHash
		}
	}
	t.Fatalf("设备 %s 未找到", deviceID)
	return ""
}

// auditEntriesForTarget 查询指定 action+target_type+target_id 的审计记录数。
func auditEntriesForTarget(t *testing.T, test *fixture, targetType string, action string, targetID string) int {
	t.Helper()
	entries, _, listErr := test.eventStore.ListAuditLog(context.Background(), store.AuditFilter{
		TargetType: targetType, TargetID: targetID, Page: 1, PageSize: 50,
	})
	require.NoError(t, listErr)
	actionCount := 0
	for _, entry := range entries {
		if entry.Action == action {
			actionCount++
		}
	}
	return actionCount
}