package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/internal/servetest"
)

// newTestStore 连接集成测试库（不可达则跳过）并清理设备表。
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "devices")
	return store.NewStore(testPool)
}

// newAuthTestRouter 构建 gin 测试路由；挂载受保护探针路由回写鉴权主体。
func newAuthTestRouter(middleware gin.HandlerFunc, probePath string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET(probePath, middleware, func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"ok": true})
	})
	return router
}

func performRequest(router *gin.Engine, method string, target string, headers map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	router.ServeHTTP(recorder, request)
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body
}

// withBearer 为请求挂上 Bearer 头，供需要原始 *http.Request 的断言用。
func withBearer(request *http.Request, token string) *http.Request {
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func TestRequireJWTMiddleware(t *testing.T) {
	const jwtSecret = "unit-test-secret"
	router := newAuthTestRouter(RequireJWT(jwtSecret), "/probe")

	// 无头 → 401
	recorder, _ := performRequest(router, http.MethodGet, "/probe", nil)
	assert.Equal(t, 401, recorder.Code)

	// 合法 Token → 200
	validToken, signErr := SignJWT(jwtSecret, "admin", time.Hour)
	require.NoError(t, signErr)
	recorder, _ = performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + validToken})
	assert.Equal(t, 200, recorder.Code)

	// 伪造 Token → 401
	forgedToken, signErr := SignJWT("another-secret", "admin", time.Hour)
	require.NoError(t, signErr)
	recorder, _ = performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + forgedToken})
	assert.Equal(t, 401, recorder.Code)

	// 过期 Token → 401
	expiredToken, signErr := SignJWT(jwtSecret, "admin", -time.Minute)
	require.NoError(t, signErr)
	recorder, _ = performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + expiredToken})
	assert.Equal(t, 401, recorder.Code)

	// 非 Bearer 头 → 401
	recorder, _ = performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Basic dXNlcjpwYXNz"})
	assert.Equal(t, 401, recorder.Code)
}

func TestRequireDeviceTokenMiddleware(t *testing.T) {
	deviceStore := newTestStore(t)
	router := newAuthTestRouter(RequireDeviceToken(deviceStore), "/probe")

	plaintextToken, generateErr := GenerateDeviceToken()
	require.NoError(t, generateErr)
	createErr := deviceStore.CreateDevice(context.Background(), &store.Device{
		DeviceID:  "dev-auth-mw",
		TokenHash: HashToken(plaintextToken),
		Hostname:  "host-a",
	})
	require.NoError(t, createErr)

	// 正确 Token → 200，且中间件挂载的设备可经 DeviceFrom 取回
	whoRouter := gin.New()
	whoRouter.GET("/who", RequireDeviceToken(deviceStore), func(ctx *gin.Context) {
		device, hasDevice := DeviceFrom(ctx)
		require.True(t, hasDevice)
		ctx.JSON(200, gin.H{"device_id": device.DeviceID})
	})
	whoRecorder := httptest.NewRecorder()
	whoRouter.ServeHTTP(whoRecorder,
		withBearer(httptest.NewRequest(http.MethodGet, "/who", nil), plaintextToken))
	assert.Equal(t, 200, whoRecorder.Code)
	assert.JSONEq(t, `{"device_id":"dev-auth-mw"}`, whoRecorder.Body.String())

	// 伪造 Token（格式合法但未注册）→ 401
	unknownToken, generateErr := GenerateDeviceToken()
	require.NoError(t, generateErr)
	forgedRecorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + unknownToken})
	assert.Equal(t, 401, forgedRecorder.Code)

	// 缺头 → 401
	missingHeaderRecorder, _ := performRequest(router, http.MethodGet, "/probe", nil)
	assert.Equal(t, 401, missingHeaderRecorder.Code)
}

func TestRequireDeviceTokenRevokedDeviceBlocked(t *testing.T) {
	deviceStore := newTestStore(t)
	router := newAuthTestRouter(RequireDeviceToken(deviceStore), "/probe")

	plaintextToken, generateErr := GenerateDeviceToken()
	require.NoError(t, generateErr)
	createErr := deviceStore.CreateDevice(context.Background(), &store.Device{
		DeviceID:  "dev-revoked-mw",
		TokenHash: HashToken(plaintextToken),
		Hostname:  "host-revoked",
	})
	require.NoError(t, createErr)

	// 吊销前：Token 有效
	activeRecorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + plaintextToken})
	assert.Equal(t, 200, activeRecorder.Code)

	// 吊销后：同一 Token 立即 401（吊销即生效），审计数据保留（设备行仍可反查）
	require.NoError(t, deviceStore.SetDeviceStatus(context.Background(), "dev-revoked-mw", "revoked"))
	revokedRecorder, revokedBody := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + plaintextToken})
	assert.Equal(t, 401, revokedRecorder.Code)
	assert.Equal(t, "设备已吊销，请联系管理员", revokedBody["error"])

	deviceRow, lookupErr := deviceStore.GetDeviceByTokenHash(context.Background(), HashToken(plaintextToken))
	require.NoError(t, lookupErr)
	assert.Equal(t, "revoked", deviceRow.Status, "吊销仅拦截访问路径，设备行与审计数据必须保留")
}
