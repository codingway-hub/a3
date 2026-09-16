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

// fakeSessionState 内存桩账号态（enabled + 代际号）。
type fakeSessionState struct {
	enabled      bool
	tokenVersion int64
}

// fakeSessionAuthStore 实现 SessionAuthStore 的内存桩：按用户名返回账号态，
// 使 RequireJWT 撤销/停用语义的测试不依赖数据库。
type fakeSessionAuthStore struct {
	users map[string]fakeSessionState
}

func (fake *fakeSessionAuthStore) GetAdminUserSessionState(ctx context.Context, username string) (bool, int64, error) {
	state, exists := fake.users[username]
	if !exists {
		return false, 0, store.ErrNotFound
	}
	return state.enabled, state.tokenVersion, nil
}

func TestRequireJWTMiddleware(t *testing.T) {
	const jwtSecret = "unit-test-secret"
	sessionStore := &fakeSessionAuthStore{users: map[string]fakeSessionState{
		"admin": {enabled: true, tokenVersion: 0},
	}}
	router := newAuthTestRouter(RequireJWT(jwtSecret, sessionStore), "/probe")

	// 无头 → 401
	recorder, _ := performRequest(router, http.MethodGet, "/probe", nil)
	assert.Equal(t, 401, recorder.Code)

	// 合法 Token → 200
	validToken, signErr := SignJWT(jwtSecret, "admin", "admin", 0, time.Hour)
	require.NoError(t, signErr)
	recorder, _ = performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + validToken})
	assert.Equal(t, 200, recorder.Code)

	// 伪造 Token → 401
	forgedToken, signErr := SignJWT("another-secret", "admin", "admin", 0, time.Hour)
	require.NoError(t, signErr)
	recorder, _ = performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + forgedToken})
	assert.Equal(t, 401, recorder.Code)

	// 过期 Token → 401
	expiredToken, signErr := SignJWT(jwtSecret, "admin", "admin", 0, -time.Minute)
	require.NoError(t, signErr)
	recorder, _ = performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + expiredToken})
	assert.Equal(t, 401, recorder.Code)

	// 非 Bearer 头 → 401
	recorder, _ = performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Basic dXNlcjpwYXNz"})
	assert.Equal(t, 401, recorder.Code)
}

// 会话撤销语义：代际号变更（停用/改角色/重置口令）即作废全部已签发 JWT，
// 不再依赖自然过期；账号停用与删除也立即失效。
func TestRequireJWTRevokesStaleSession(t *testing.T) {
	const jwtSecret = "unit-test-secret"
	sessionStore := &fakeSessionAuthStore{users: map[string]fakeSessionState{
		"boss": {enabled: true, tokenVersion: 1},
	}}
	router := newAuthTestRouter(RequireJWT(jwtSecret, sessionStore), "/probe")

	// 与库内代际号一致 → 放行
	currentToken, signErr := SignJWT(jwtSecret, "boss", "admin", 1, time.Hour)
	require.NoError(t, signErr)
	recorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + currentToken})
	assert.Equal(t, 200, recorder.Code)

	// 改角色/停用（代际号自增到 2）后，签发于版本 1 的旧 token 立即失效
	sessionStore.users["boss"] = fakeSessionState{enabled: true, tokenVersion: 2}
	staleRecorder, staleBody := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + currentToken})
	assert.Equal(t, 401, staleRecorder.Code)
	assert.Equal(t, "登录已失效，请重新登录", staleBody["error"])

	// 账号停用 → 401（统一失效文案，不泄露具体原因）
	sessionStore.users["boss"] = fakeSessionState{enabled: false, tokenVersion: 2}
	disabledRecorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + currentToken})
	assert.Equal(t, 401, disabledRecorder.Code)

	// 账号不存在（删除后）→ 401
	ghostToken, signErr := SignJWT(jwtSecret, "ghost", "admin", 999, time.Hour)
	require.NoError(t, signErr)
	missingRecorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + ghostToken})
	assert.Equal(t, 401, missingRecorder.Code)

	// 管理员恢复启用（代际号随状态变更再自增到 3）：用最新代际号重新登录签发的
	// Token 放行，而此前签发的旧 Token 依旧失效。
	sessionStore.users["boss"] = fakeSessionState{enabled: true, tokenVersion: 3}
	freshToken, signErr := SignJWT(jwtSecret, "boss", "admin", 3, time.Hour)
	require.NoError(t, signErr)
	freshRecorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + freshToken})
	assert.Equal(t, 200, freshRecorder.Code)
	stillStaleRecorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + currentToken})
	assert.Equal(t, 401, stillStaleRecorder.Code)
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
	assert.Equal(t, "设备已吊销或禁用，请联系管理员", revokedBody["error"])

	deviceRow, lookupErr := deviceStore.GetDeviceByTokenHash(context.Background(), HashToken(plaintextToken))
	require.NoError(t, lookupErr)
	assert.Equal(t, "revoked", deviceRow.Status, "吊销仅拦截访问路径，设备行与审计数据必须保留")
}

// 禁用态（disabled）与吊销同为即时效用切断：Token 立即 401，行与审计数据保留。
func TestRequireDeviceTokenDisabledBlocked(t *testing.T) {
	deviceStore := newTestStore(t)
	router := newAuthTestRouter(RequireDeviceToken(deviceStore), "/probe")

	plaintextToken, generateErr := GenerateDeviceToken()
	require.NoError(t, generateErr)
	createErr := deviceStore.CreateDevice(context.Background(), &store.Device{
		DeviceID:  "dev-disabled-mw",
		TokenHash: HashToken(plaintextToken),
		Hostname:  "host-disabled",
	})
	require.NoError(t, createErr)

	// 禁用前：Token 有效
	activeRecorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + plaintextToken})
	assert.Equal(t, 200, activeRecorder.Code)

	require.NoError(t, deviceStore.SetDeviceStatus(context.Background(), "dev-disabled-mw", "disabled"))
	disabledRecorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + plaintextToken})
	assert.Equal(t, 401, disabledRecorder.Code)
}

// 设备 Token 到期（TTL 配置后）即失效：过期一律 401，须重新注册或管理员换发。
func TestRequireDeviceTokenExpiredBlocked(t *testing.T) {
	deviceStore := newTestStore(t)
	router := newAuthTestRouter(RequireDeviceToken(deviceStore), "/probe")

	plaintextToken, generateErr := GenerateDeviceToken()
	require.NoError(t, generateErr)
	pastTime := time.Now().Add(-time.Hour)
	createErr := deviceStore.CreateDevice(context.Background(), &store.Device{
		DeviceID:       "dev-expire-mw",
		TokenHash:      HashToken(plaintextToken),
		Hostname:       "host-expired",
		TokenExpiresAt: &pastTime,
	})
	require.NoError(t, createErr)

	expiredRecorder, expiredBody := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + plaintextToken})
	assert.Equal(t, 401, expiredRecorder.Code)
	assert.Equal(t, "设备 Token 已过期，请联系管理员换发", expiredBody["error"])

	// 到期末到（未来时间）的 Token 不受影响 → 200
	futureToken, generateErr := GenerateDeviceToken()
	require.NoError(t, generateErr)
	futureTime := time.Now().Add(time.Hour)
	createErr = deviceStore.CreateDevice(context.Background(), &store.Device{
		DeviceID:       "dev-expire-ok",
		TokenHash:      HashToken(futureToken),
		Hostname:       "host-future",
		TokenExpiresAt: &futureTime,
	})
	require.NoError(t, createErr)
	okRecorder, _ := performRequest(router, http.MethodGet, "/probe",
		map[string]string{"Authorization": "Bearer " + futureToken})
	assert.Equal(t, 200, okRecorder.Code)
}

func TestRequireRoleMiddleware(t *testing.T) {
	const jwtSecret = "unit-test-secret"
	sessionStore := &fakeSessionAuthStore{users: map[string]fakeSessionState{
		"boss": {enabled: true, tokenVersion: 0},
		"aud":  {enabled: true, tokenVersion: 0},
	}}
	roleRouter := gin.New()
	roleRouter.GET("/admin-only",
		RequireJWT(jwtSecret, sessionStore), RequireRole("admin"),
		func(ctx *gin.Context) {
			username, _ := UsernameFrom(ctx)
			role, _ := RoleFrom(ctx)
			ctx.JSON(200, gin.H{"username": username, "role": role})
		})

	// admin Token → 200，且上下文角色可取回
	adminToken, signErr := SignJWT(jwtSecret, "boss", "admin", 0, time.Hour)
	require.NoError(t, signErr)
	adminRecorder, adminBody := performRequest(roleRouter, http.MethodGet, "/admin-only",
		map[string]string{"Authorization": "Bearer " + adminToken})
	assert.Equal(t, 200, adminRecorder.Code)
	assert.Equal(t, "admin", adminBody["role"])

	// auditor Token 命中 admin-only → 403
	auditorToken, auditorSignErr := SignJWT(jwtSecret, "aud", "auditor", 0, time.Hour)
	require.NoError(t, auditorSignErr)
	auditorRecorder, auditorBody := performRequest(roleRouter, http.MethodGet, "/admin-only",
		map[string]string{"Authorization": "Bearer " + auditorToken})
	assert.Equal(t, 403, auditorRecorder.Code)
	assert.Equal(t, "权限不足", auditorBody["error"])

	// 多角色允许集合：auditor 在 {admin, auditor} 中放行
	sharedRouter := gin.New()
	sharedRouter.GET("/shared", RequireJWT(jwtSecret, sessionStore), RequireRole("admin", "auditor"),
		func(ctx *gin.Context) { ctx.JSON(200, gin.H{"ok": true}) })
	sharedRecorder, _ := performRequest(sharedRouter, http.MethodGet, "/shared",
		map[string]string{"Authorization": "Bearer " + auditorToken})
	assert.Equal(t, 200, sharedRecorder.Code)
}
