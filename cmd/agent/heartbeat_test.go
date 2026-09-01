package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/agent/core/spool"
	"github.com/codingway-hub/a3/internal/agent/core/transport"
)

// capturedHeartbeat 测试服务端捕获的单次心跳请求。
type capturedHeartbeat struct {
	Batches int64
	Bytes   int64
}

// startHeartbeatCollector 返回一个计数心跳命中、可选注入响应码的测试服务端。
func startHeartbeatCollector(t *testing.T, statusCode int, recorded *[]capturedHeartbeat) *httptest.Server {
	t.Helper()
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/api/v1/agent/heartbeat", request.URL.Path)
		var received captureBody
		_ = json.NewDecoder(request.Body).Decode(&received)
		*recorded = append(*recorded, capturedHeartbeat{Batches: received.Batches, Bytes: received.Bytes})
		if statusCode == http.StatusOK {
			_, _ = responseWriter.Write([]byte(`{"ok":true}`))
		} else {
			http.Error(responseWriter, `{"error":"拒绝"}`, statusCode)
		}
	}))
	t.Cleanup(fakeServer.Close)
	return fakeServer
}

type captureBody struct {
	Batches int64 `json:"spool_pending_batches"`
	Bytes   int64 `json:"spool_pending_bytes"`
}

func TestHeartbeatLoopDisabledExitsImmediately(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("心跳被关闭后不应发出任何请求")
	}))
	defer fakeServer.Close()

	uploaderClient, buildErr := transport.NewUploader(fakeServer.URL, "a3d_test", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, newErr := spool.New(filepath.Join(t.TempDir(), "spool"), 0)
	require.NoError(t, newErr)

	quietLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	loopDone := make(chan struct{})
	go heartbeatLoop(context.Background(), uploaderClient, spoolQueue, 0, quietLogger, loopDone)

	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("关闭心跳时循环应立即退出")
	}
}

func TestHeartbeatLoopReportsBacklogThenStopsOnCancel(t *testing.T) {
	recorded := make([]capturedHeartbeat, 0)
	fakeServer := startHeartbeatCollector(t, http.StatusOK, &recorded)

	uploaderClient, buildErr := transport.NewUploader(fakeServer.URL, "a3d_test", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, newErr := spool.New(filepath.Join(t.TempDir(), "spool"), 0)
	require.NoError(t, newErr)
	require.NoError(t, spoolQueue.Enqueue([]byte(`{"events":[{"event_id":"cached-1"}]}`)))

	loopCtx, cancelLoop := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go heartbeatLoop(loopCtx, uploaderClient, spoolQueue, 20*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)), loopDone)

	deadline := time.Now().Add(2 * time.Second)
	for len(recorded) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancelLoop()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("心跳循环未在取消后及时退出")
	}

	require.NotEmpty(t, recorded, "周期心跳应至少命中一次")
	assert.EqualValues(t, 1, recorded[0].Batches, "断网缓存中的批次应上报为积压")
	assert.True(t, recorded[0].Bytes > 0, "积压字节数应为真实文件大小")
}

func TestHeartbeatLoopStopsOnAuthFailure(t *testing.T) {
	var hitCount atomic.Int32
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		hitCount.Add(1)
		http.Error(responseWriter, `{"error":"设备已吊销"}`, http.StatusUnauthorized)
	}))
	defer fakeServer.Close()

	uploaderClient, buildErr := transport.NewUploader(fakeServer.URL, "a3d_revoked", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, newErr := spool.New(filepath.Join(t.TempDir(), "spool"), 0)
	require.NoError(t, newErr)

	loopDone := make(chan struct{})
	go heartbeatLoop(context.Background(), uploaderClient, spoolQueue,
		20*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)), loopDone)

	// 401 属鉴权失效：循环应在首次心跳后自行停止（ctx 仍活跃也不应空转）
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("鉴权失败后心跳循环应停止")
	}
	assert.EqualValues(t, 1, hitCount.Load(), "鉴权失败只允许一次尝试，之后必须停表")
}

func TestHeartbeatLoopSurvivesTransientFailure(t *testing.T) {
	var attemptCount atomic.Int32
	var successCount atomic.Int32
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if attemptCount.Add(1) <= 1 {
			http.Error(responseWriter, `{"error":"服务端暂时不可用"}`, http.StatusInternalServerError)
			return
		}
		successCount.Add(1)
		_, _ = responseWriter.Write([]byte(`{"ok":true}`))
	}))
	defer fakeServer.Close()

	uploaderClient, buildErr := transport.NewUploader(fakeServer.URL, "a3d_test", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, newErr := spool.New(filepath.Join(t.TempDir(), "spool"), 0)
	require.NoError(t, newErr)

	loopCtx, cancelLoop := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go heartbeatLoop(loopCtx, uploaderClient, spoolQueue,
		30*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)), loopDone)

	// 首次 500 走退避；恢复后下一拍应成功上报（瞬时可重试 ≠ 停止心跳）
	deadline := time.Now().Add(3 * time.Second)
	for successCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancelLoop()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("心跳循环未在取消后及时退出")
	}

	assert.True(t, successCount.Load() >= 1, "瞬时故障恢复后心跳应继续成功上报")
}