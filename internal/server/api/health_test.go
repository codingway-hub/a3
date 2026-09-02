package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/store"
)

// TestHealthzOK 存活探针公开可用（无 token）：DB 可达返回 200 ok。
func TestHealthzOK(t *testing.T) {
	test := newFixture(t)

	recorder := test.do(http.MethodGet, "/healthz", "", "")
	require.Equal(t, http.StatusOK, recorder.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "ok", body["status"])
	assert.Equal(t, "ok", body["db"])
	assert.Equal(t, "test", body["version"])
	assert.GreaterOrEqual(t, body["uptime_seconds"], float64(0))
	probeTime, ok := body["time"].(string)
	require.True(t, ok)
	_, parseErr := time.Parse(time.RFC3339, probeTime)
	assert.NoError(t, parseErr)
}

// TestHealthzDegradedWhenDBDown DB 不可达返回 503 degraded。
// 死端口延迟建池，不与真实集成库交互，因此不走 newFixture（其 ReloadRules 需活库）。
func TestHealthzDegradedWhenDBDown(t *testing.T) {
	deadPool, poolErr := pgxpool.New(context.Background(),
		"postgres://a3:a3@127.0.0.1:1/a3_test?sslmode=disable") // 惰性建池，不立刻触发连接
	require.NoError(t, poolErr)
	defer deadPool.Close()

	engine := NewRouter(store.NewStore(deadPool), nil, RouterConfig{Version: "test"}).Setup()

	recorder := doRequest(engine, http.MethodGet, "/healthz")
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "degraded", body["status"])
	assert.Equal(t, "error", body["db"])
}

// TestHealthzNilStoreNoPanic 空装配（install_routes_test 的 NewRouter(nil, nil, ...) 模式）
// 打到 /healthz 时不得 panic，返回 503。
func TestHealthzNilStoreNoPanic(t *testing.T) {
	engine := NewRouter(nil, nil, RouterConfig{}).Setup()

	recorder := doRequest(engine, http.MethodGet, "/healthz")
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "degraded", body["status"])
	assert.Equal(t, "error", body["db"])
}

// doRequest 对给定引擎直发一次请求（无 body），供非 newFixture 用例使用。
func doRequest(engine interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}, method string, path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, nil)
	engine.ServeHTTP(recorder, request)
	return recorder
}