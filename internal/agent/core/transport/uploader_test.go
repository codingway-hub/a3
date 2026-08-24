package transport

import (
	"context"
	"encoding/json"
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
				_, _ = responseWriter.Write([]byte(`{"device_id":"dev-xyz","token":"a3d_fresh"}`))
				return
			}
			http.Error(responseWriter, `{"error":"自动注册已关闭"}`, http.StatusForbidden)
			return
		}
		responseWriter.WriteHeader(http.StatusNotFound)
	}))
	defer fakeServer.Close()

	testUploader := newTestUploader(t, fakeServer.URL)
	registration, registerErr := testUploader.RegisterDevice(context.Background(),
		DeviceInfo{Hostname: "mac", OS: "darwin", Arch: "arm64", MachineFingerprint: "fp-ok"})
	require.NoError(t, registerErr)
	assert.Equal(t, RegistrationResult{DeviceID: "dev-xyz", Token: "a3d_fresh"}, registration)

	_, rejectedErr := testUploader.RegisterDevice(context.Background(),
		DeviceInfo{Hostname: "mac", MachineFingerprint: "fp-closed"})
	require.Error(t, rejectedErr)
	assert.Contains(t, rejectedErr.Error(), "403")
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
