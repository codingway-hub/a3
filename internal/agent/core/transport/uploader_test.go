package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/pkg/schema"
)

// newTestUploader 构建指向测试服务、退避极短的上报客户端。
func newTestUploader(t *testing.T, serverURL string) *Uploader {
	t.Helper()
	testUploader, buildErr := NewUploader(serverURL, "a3d_test-token", "1.0.0", false, nil)
	require.NoError(t, buildErr)
	testUploader.retryInitial = time.Millisecond
	testUploader.retryCap = 5 * time.Millisecond
	return testUploader
}

func sampleEvent(eventID string) schema.Event {
	return schema.Event{
		EventID: eventID, EventType: schema.EventTypeConversation, Role: "user",
		AgentType: schema.AgentTypeClaudeCode, SessionID: "sess-t", DeviceID: "dev-t",
		OccurredAt: time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC),
		Content:    "内容-" + eventID, SourceMethod: schema.SourceMethodFileLog,
	}
}

func TestPostBatchSuccessCarriesAuthAndEnvelope(t *testing.T) {
	var seenAuthorization, seenContentType string
	var receivedEnvelope batchEnvelope

	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/api/v1/events/batch", request.URL.Path)
		seenAuthorization = request.Header.Get("Authorization")
		seenContentType = request.Header.Get("Content-Type")
		require.NoError(t, json.NewDecoder(request.Body).Decode(&receivedEnvelope))
		responseWriter.Header().Set("Content-Type", "application/json")
		_, _ = responseWriter.Write([]byte(`{"accepted":2,"duplicates":1}`))
	}))
	defer fakeServer.Close()

	testUploader := newTestUploader(t, fakeServer.URL)
	batchResult, postErr := testUploader.PostBatch(context.Background(),
		[]schema.Event{sampleEvent("evt-1"), sampleEvent("evt-2")})
	require.NoError(t, postErr)

	assert.Equal(t, "Bearer a3d_test-token", seenAuthorization)
	assert.Equal(t, "application/json", seenContentType)
	assert.Equal(t, "1.0.0", receivedEnvelope.AgentVersion)
	assert.Equal(t, []string{"claude-code"}, receivedEnvelope.Plugins)
	require.Len(t, receivedEnvelope.Events, 2)
	assert.Equal(t, []int{2, 1}, []int{batchResult.Accepted, batchResult.Duplicates})
}

func TestPostBatchRetriesOn5xxThenSucceeds(t *testing.T) {
	var attemptCount atomic.Int32

	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if attemptCount.Add(1) <= 2 {
			http.Error(responseWriter, `{"error":"数据库瞬断"}`, http.StatusInternalServerError)
			return
		}
		_, _ = responseWriter.Write([]byte(`{"accepted":1,"duplicates":0}`))
	}))
	defer fakeServer.Close()

	testUploader := newTestUploader(t, fakeServer.URL)
	batchResult, postErr := testUploader.PostBatch(context.Background(), []schema.Event{sampleEvent("evt-r")})
	require.NoError(t, postErr)
	assert.EqualValues(t, 3, attemptCount.Load(), "前两次 500 应退避重试，第三次成功")
	assert.Equal(t, 1, batchResult.Accepted)
}

func TestPostBatchGivesUpImmediatelyOn401(t *testing.T) {
	var attemptCount atomic.Int32

	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		attemptCount.Add(1)
		http.Error(responseWriter, `{"error":"设备令牌无效"}`, http.StatusUnauthorized)
	}))
	defer fakeServer.Close()

	testUploader := newTestUploader(t, fakeServer.URL)
	_, postErr := testUploader.PostBatch(context.Background(), []schema.Event{sampleEvent("evt-401")})
	require.Error(t, postErr)

	var nonRetryableErr *NonRetryableError
	require.ErrorAs(t, postErr, &nonRetryableErr)
	assert.Equal(t, http.StatusUnauthorized, nonRetryableErr.StatusCode)
	assert.Contains(t, nonRetryableErr.Detail, "设备令牌无效")
	assert.EqualValues(t, 1, attemptCount.Load(), "不可重试错误不得触发第二次尝试")
}

func TestPostBatchRetriesOn429(t *testing.T) {
	var attemptCount atomic.Int32

	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if attemptCount.Add(1) <= 2 {
			http.Error(responseWriter, `{"error":"限流"}`, http.StatusTooManyRequests)
			return
		}
		_, _ = responseWriter.Write([]byte(`{"accepted":1,"duplicates":0}`))
	}))
	defer fakeServer.Close()

	testUploader := newTestUploader(t, fakeServer.URL)
	batchResult, postErr := testUploader.PostBatch(context.Background(), []schema.Event{sampleEvent("evt-429")})
	require.NoError(t, postErr)
	assert.EqualValues(t, 3, attemptCount.Load(), "429 应归可重试分支按退避重试")
	assert.Equal(t, 1, batchResult.Accepted)
}

// TestPostBatchOnceSingleShotNoInternalRetry 钉住单次尝试语义：
// 重放路径以 PostBatchOnce 单发，429/5xx 也立即返回，退避节奏交重放循环裁决。
func TestPostBatchOnceSingleShotNoInternalRetry(t *testing.T) {
	var attemptCount atomic.Int32

	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		attemptCount.Add(1)
		http.Error(responseWriter, "busy", http.StatusServiceUnavailable)
	}))
	defer fakeServer.Close()

	testUploader := newTestUploader(t, fakeServer.URL)
	_, onceErr := testUploader.PostBatchOnce(context.Background(), []schema.Event{sampleEvent("evt-once")})
	require.Error(t, onceErr)
	assert.EqualValues(t, 1, attemptCount.Load(), "PostBatchOnce 不做内部退避重试")

	var nonRetryableErr *NonRetryableError
	assert.False(t, errors.As(onceErr, &nonRetryableErr), "5xx 在单次尝试下仍属可重试")
}

func TestPostBatchContextCancelDuringBackoff(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		http.Error(responseWriter, "down", http.StatusServiceUnavailable)
	}))
	defer fakeServer.Close()

	testUploader := newTestUploader(t, fakeServer.URL)
	slowUploader := &Uploader{
		serverBaseURL: testUploader.serverBaseURL,
		deviceToken:   testUploader.deviceToken,
		agentVersion:  testUploader.agentVersion,
		plugins:       testUploader.plugins,
		httpClient:    testUploader.httpClient,
		logger:        testUploader.logger,
		retryInitial:  10 * time.Second,
		retryCap:      60 * time.Second,
	}

	ctxWithCancel, cancelFunc := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelFunc()
	_, postErr := slowUploader.PostBatch(ctxWithCancel, []schema.Event{sampleEvent("evt-slow")})
	require.Error(t, postErr)
	assert.Contains(t, postErr.Error(), "取消")
}

func TestRegisterDeviceParsesResultAndRejectsErrors(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/devices/register" && request.Method == http.MethodPost {
			var registerRequest map[string]any
			require.NoError(t, json.NewDecoder(request.Body).Decode(&registerRequest))
			if registerRequest["machine_fingerprint"] == "fp-ok" {
				require.Equal(t, "a3i_abcdef", registerRequest["install_code"], "安装凭据应随注册请求体提交")
				_, _ = responseWriter.Write([]byte(`{"device_id":"dev-xyz","token":"a3d_fresh"}`))
				return
			}
			if registerRequest["machine_fingerprint"] == "fp-auth" {
				if request.Header.Get("Authorization") == "Bearer a3d_existing" {
					_, _ = responseWriter.Write([]byte(`{"device_id":"dev-auth","token":"a3d_rotated"}`))
					return
				}
				http.Error(responseWriter, `{"error":"设备已存在：注册须携带当前 Token"}`, http.StatusConflict)
				return
			}
			http.Error(responseWriter, `{"error":"安装凭据无效"}`, http.StatusForbidden)
			return
		}
		responseWriter.WriteHeader(http.StatusNotFound)
	}))
	defer fakeServer.Close()

	testUploader := newTestUploader(t, fakeServer.URL)
	registration, registerErr := testUploader.RegisterDevice(context.Background(),
		DeviceInfo{Hostname: "mac", OS: "darwin", Arch: "arm64", MachineFingerprint: "fp-ok",
			InstallCode: "a3i_abcdef"}, "")
	require.NoError(t, registerErr)
	assert.Equal(t, RegistrationResult{DeviceID: "dev-xyz", Token: "a3d_fresh"}, registration)

	_, rejectedErr := testUploader.RegisterDevice(context.Background(),
		DeviceInfo{Hostname: "mac", MachineFingerprint: "fp-closed"}, "")
	require.Error(t, rejectedErr)
	assert.Contains(t, rejectedErr.Error(), "403")

	// 凭证随注册请求透传：未携带 → 409，携带既有 Token → 轮换成功
	_, noCredentialErr := testUploader.RegisterDevice(context.Background(),
		DeviceInfo{Hostname: "mac", MachineFingerprint: "fp-auth"}, "")
	require.Error(t, noCredentialErr)
	assert.Contains(t, noCredentialErr.Error(), "409")
	withCredentialRegistration, credentialErr := testUploader.RegisterDevice(context.Background(),
		DeviceInfo{Hostname: "mac", MachineFingerprint: "fp-auth"}, "a3d_existing")
	require.NoError(t, credentialErr)
	assert.Equal(t, "a3d_rotated", withCredentialRegistration.Token)
}

func TestNewUploaderValidationAndInsecureFlag(t *testing.T) {
	_, emptyURLErr := NewUploader("", "", "", false, nil)
	assert.Error(t, emptyURLErr)

	insecureUploader, insecureErr := NewUploader("https://127.0.0.1:8080", "", "", true, nil)
	require.NoError(t, insecureErr)
	require.NotNil(t, insecureUploader.httpClient.Transport, "insecure 开关应注入自定义 Transport")
	transport, ok := insecureUploader.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestGetDeviceRulesCarriesAuthAndParses(t *testing.T) {
	var seenAuthorization, seenPath string
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		seenAuthorization = request.Header.Get("Authorization")
		seenPath = request.URL.Path
		responseWriter.Write([]byte(`{"revision":"sha256:abc","rules":[{"id":"dlp.jwt","name":"JWT 令牌泄露",` +
			`"category":"dlp","target":"any","patterns":["eyJ"],"path_globs":[],"severity":"high","action":"block"}]}`))
	}))
	defer fakeServer.Close()

	testUploader := newTestUploader(t, fakeServer.URL)
	rulesPayload, fetchErr := testUploader.GetDeviceRules(context.Background())
	require.NoError(t, fetchErr)
	assert.Equal(t, "Bearer a3d_test-token", seenAuthorization)
	assert.Equal(t, "/api/v1/devices/rules", seenPath)
	assert.Equal(t, "sha256:abc", rulesPayload.Revision)
	require.Len(t, rulesPayload.Rules, 1)
	assert.Equal(t, "dlp.jwt", rulesPayload.Rules[0].ID)
}

func TestGetDeviceRulesClassifiesFailures(t *testing.T) {
	rejectServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.WriteHeader(http.StatusUnauthorized)
	}))
	defer rejectServer.Close()
	_, fetchErr := newTestUploader(t, rejectServer.URL).GetDeviceRules(context.Background())
	var nonRetryableErr *NonRetryableError
	require.ErrorAs(t, fetchErr, &nonRetryableErr)
	assert.Equal(t, http.StatusUnauthorized, nonRetryableErr.StatusCode)

	unavailableServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.WriteHeader(http.StatusBadGateway)
	}))
	defer unavailableServer.Close()
	_, fetchErr = newTestUploader(t, unavailableServer.URL).GetDeviceRules(context.Background())
	assert.NotErrorAs(t, fetchErr, &nonRetryableErr, "5xx 应视为可重试类错误")

	tokenlessUploader, buildErr := NewUploader("http://127.0.0.1:1", "", "1.0.0", false, nil)
	require.NoError(t, buildErr)
	_, fetchErr = tokenlessUploader.GetDeviceRules(context.Background())
	require.ErrorAs(t, fetchErr, &nonRetryableErr, "无 Token 直接归类不可重试")
}

func TestHeartbeatPostsBacklogAndClassifiesFailures(t *testing.T) {
	type receivedHeartbeat struct {
		SpoolPendingBatches int64 `json:"spool_pending_batches"`
		SpoolPendingBytes   int64 `json:"spool_pending_bytes"`
	}

	t.Run("成功上报积压且认证正确", func(t *testing.T) {
		var seenAuthorization string
		var seenPath string
		var receivedBody receivedHeartbeat
		fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			seenPath = request.URL.Path
			seenAuthorization = request.Header.Get("Authorization")
			require.NoError(t, json.NewDecoder(request.Body).Decode(&receivedBody))
			_, _ = responseWriter.Write([]byte(`{"ok":true,"device_id":"dev-t"}`))
		}))
		defer fakeServer.Close()

		testUploader := newTestUploader(t, fakeServer.URL)
		require.NoError(t, testUploader.Heartbeat(context.Background(), 7, 4096))

		assert.Equal(t, "/api/v1/agent/heartbeat", seenPath)
		assert.Equal(t, "Bearer a3d_test-token", seenAuthorization)
		assert.Equal(t, int64(7), receivedBody.SpoolPendingBatches)
		assert.Equal(t, int64(4096), receivedBody.SpoolPendingBytes)
	})

	t.Run("5xx 视为瞬时可重试", func(t *testing.T) {
		fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			http.Error(responseWriter, `{"error":"内部错误"}`, http.StatusInternalServerError)
		}))
		defer fakeServer.Close()

		testUploader := newTestUploader(t, fakeServer.URL)
		heartbeatErr := testUploader.Heartbeat(context.Background(), 0, 0)
		require.Error(t, heartbeatErr)
		var nonRetryableErr *NonRetryableError
		assert.False(t, errors.As(heartbeatErr, &nonRetryableErr), "5xx 不应归类为拒绝类错误")
	})

	t.Run("401 归类 NonRetryableError 供调用方停止心跳", func(t *testing.T) {
		fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			http.Error(responseWriter, `{"error":"设备已吊销"}`, http.StatusUnauthorized)
		}))
		defer fakeServer.Close()

		testUploader := newTestUploader(t, fakeServer.URL)
		heartbeatErr := testUploader.Heartbeat(context.Background(), 0, 0)
		require.Error(t, heartbeatErr)
		var nonRetryableErr *NonRetryableError
		require.ErrorAs(t, heartbeatErr, &nonRetryableErr)
		assert.Equal(t, http.StatusUnauthorized, nonRetryableErr.StatusCode)
	})
}
