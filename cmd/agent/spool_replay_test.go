// spool_replay_test.go —— 本地缓存重放分类处置回归：解码损坏/鉴权失效/明确拒绝/
// 限流/成功五种分类的决策与证据留存，以及整循环对吊销令牌的「放回绝不烧库」行为。
package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/internal/agent/core/spool"
	"github.com/codingway-hub/a3/internal/agent/core/transport"
	"github.com/codingway-hub/a3/pkg/schema"
)

// replayEnvelopeBytes 构造一条可重放的事件信封（DeviceID 置空以便验证填设备身份）。
func replayEnvelopeBytes(t *testing.T) []byte {
	t.Helper()
	envelopeBytes, marshalErr := json.Marshal(core.EventEnvelope{
		AgentVersion: agentVersion,
		Plugins:      []string{"claude-code"},
		Events: []schema.Event{{
			EventID: "evt-replay-1", EventType: schema.EventTypeConversation, Role: "user",
			AgentType: schema.AgentTypeClaudeCode, SessionID: "sess-r",
			OccurredAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
			Content:    "重放内容",
		}},
	})
	require.NoError(t, marshalErr)
	return envelopeBytes
}

// dequeueSingleBatch 在临时 spool 里入队一条并取出租约，供单批次分类断言。
func dequeueSingleBatch(t *testing.T, batchPayload []byte) (*spool.Spool, *spool.Batch) {
	t.Helper()
	spoolQueue, newErr := spool.New(filepath.Join(t.TempDir(), "spool"), 0)
	require.NoError(t, newErr)
	require.NoError(t, spoolQueue.Enqueue(batchPayload))
	inflightBatch, dequeueErr := spoolQueue.Dequeue()
	require.NoError(t, dequeueErr)
	return spoolQueue, inflightBatch
}

// quarantineNames 返回隔离区归档文件名（不存在则视为空）。
func quarantineNames(t *testing.T, spoolQueue *spool.Spool) []string {
	t.Helper()
	return spoolDirNames(t, spoolQueue, "quarantine")
}

// reservedIncoming 返回 incoming 队列文件名（不存在则视为空）。
func reservedIncoming(t *testing.T, spoolQueue *spool.Spool) []string {
	t.Helper()
	return spoolDirNames(t, spoolQueue, "incoming")
}

// spoolDirNames 读取 spool 根下某子目录的文件名（跳过子目录）。
func spoolDirNames(t *testing.T, spoolQueue *spool.Spool, subdirectoryName string) []string {
	t.Helper()
	dirEntries, readErr := os.ReadDir(filepath.Join(spoolQueue.Directory(), subdirectoryName))
	if os.IsNotExist(readErr) {
		return nil
	}
	require.NoError(t, readErr)
	names := make([]string, 0, len(dirEntries))
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {
			names = append(names, dirEntry.Name())
		}
	}
	return names
}

func TestReplaySingleBatchUnauthorizedRestoresNotBurns(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		http.Error(responseWriter, `{"error":"设备已吊销"}`, http.StatusUnauthorized)
	}))
	defer fakeServer.Close()

	uploaderClient, buildErr := transport.NewUploader(fakeServer.URL, "a3d_revoked", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, inflightBatch := dequeueSingleBatch(t, replayEnvelopeBytes(t))

	decision, classifyErr := replaySingleBatch(context.Background(), uploaderClient, "dev-agent-test", inflightBatch)
	require.NoError(t, classifyErr)
	assert.Equal(t, replayRetrySlow, decision, "鉴权失效应放回 + 长退避，不归档不烧库")
	assert.Empty(t, quarantineNames(t, spoolQueue), "拒绝对待单位: 401 不得归档")

	require.NoError(t, inflightBatch.Restore(), "循环动作：放回原位")
	queueLength, lengthErr := spoolQueue.Len()
	require.NoError(t, lengthErr)
	assert.Equal(t, 1, queueLength, "吊销后证据留在队列等恢复续传")
}

func TestReplaySingleBatchBadRequestQuarantinesEvidence(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		http.Error(responseWriter, `{"error":"事件字段非法"}`, http.StatusBadRequest)
	}))
	defer fakeServer.Close()

	uploaderClient, buildErr := transport.NewUploader(fakeServer.URL, "a3d_test", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, inflightBatch := dequeueSingleBatch(t, replayEnvelopeBytes(t))

	decision, classifyErr := replaySingleBatch(context.Background(), uploaderClient, "dev-agent-test", inflightBatch)
	require.NoError(t, classifyErr)
	assert.Equal(t, replayQuarantine, decision, "400 载荷永久非法应归档")

	quarantinedNames := quarantineNames(t, spoolQueue)
	require.Len(t, quarantinedNames, 1, "400 批次应归档留证")
	assert.Contains(t, quarantinedNames[0], ".q-reject-400", "归档文件名应标记原因")
	assert.Empty(t, reservedIncoming(t, spoolQueue), "归档后队列应清空")
}

func TestReplaySingleBatchCorruptPayloadQuarantines(t *testing.T) {
	// 不依赖服务端：信封内容本身不可解码即归档，证据保留不阻塞后续
	uploaderClient, buildErr := transport.NewUploader("http://127.0.0.1:1", "a3d_test", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, inflightBatch := dequeueSingleBatch(t, []byte(`{"events":[`)) // 截断 JSON

	decision, classifyErr := replaySingleBatch(context.Background(), uploaderClient, "dev-agent-test", inflightBatch)
	require.NoError(t, classifyErr)
	assert.Equal(t, replayQuarantine, decision, "解码失败应归档")

	quarantinedNames := quarantineNames(t, spoolQueue)
	require.Len(t, quarantinedNames, 1)
	assert.Contains(t, quarantinedNames[0], ".q-corrupt", "损坏批次标记 corrupt")
}

func TestReplaySingleBatchRateLimitedRetriesFast(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		http.Error(responseWriter, `{"error":"限流"}`, http.StatusTooManyRequests)
	}))
	defer fakeServer.Close()

	uploaderClient, buildErr := transport.NewUploader(fakeServer.URL, "a3d_test", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, inflightBatch := dequeueSingleBatch(t, replayEnvelopeBytes(t))

	decision, classifyErr := replaySingleBatch(context.Background(), uploaderClient, "dev-agent-test", inflightBatch)
	require.NoError(t, classifyErr)
	assert.Equal(t, replayRetryFast, decision, "429 应归瞬时可重试（短退避）")

	require.NoError(t, inflightBatch.Restore())
	queueLength, lengthErr := spoolQueue.Len()
	require.NoError(t, lengthErr)
	assert.Equal(t, 1, queueLength, "限流后批次应放回重试")
	assert.Empty(t, quarantineNames(t, spoolQueue))
}

func TestReplaySingleBatchSuccessCommits(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.Header().Set("Content-Type", "application/json")
		_, _ = responseWriter.Write([]byte(`{"accepted":1,"duplicates":0}`))
	}))
	defer fakeServer.Close()

	uploaderClient, buildErr := transport.NewUploader(fakeServer.URL, "a3d_test", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, inflightBatch := dequeueSingleBatch(t, replayEnvelopeBytes(t))

	decision, classifyErr := replaySingleBatch(context.Background(), uploaderClient, "dev-agent-test", inflightBatch)
	require.NoError(t, classifyErr)
	assert.Equal(t, replayCommit, decision, "上报成功应 Commit")

	require.NoError(t, inflightBatch.Commit())
	queueLength, lengthErr := spoolQueue.Len()
	require.NoError(t, lengthErr)
	assert.Equal(t, 0, queueLength, "成功后队列清空")
}

// TestSpoolReplayLoopRevokedTokenLeavesEvidence 整循环行为：设备被吊销（401）时
// 在途批次被放回（Restore）而非烧库归档，长退避期间可被优雅关闭打断。
func TestSpoolReplayLoopRevokedTokenLeavesEvidence(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		http.Error(responseWriter, `{"error":"设备已吊销"}`, http.StatusUnauthorized)
	}))
	defer fakeServer.Close()

	uploaderClient, buildErr := transport.NewUploader(fakeServer.URL, "a3d_revoked", agentVersion, false, nil)
	require.NoError(t, buildErr)
	spoolQueue, newErr := spool.New(filepath.Join(t.TempDir(), "spool"), 0)
	require.NoError(t, newErr)
	require.NoError(t, spoolQueue.Enqueue(replayEnvelopeBytes(t)))

	quietLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	loopCtx, cancelLoop := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go spoolReplayLoop(loopCtx, spoolQueue, uploaderClient, "dev-agent-test", quietLogger, loopDone)

	// 给循环一轮 Dequeue→分类→Restore 的时间，随后优雅关闭打断长退避
	time.Sleep(300 * time.Millisecond)
	cancelLoop()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("重放循环未在取消后及时退出")
	}

	queueLength, lengthErr := spoolQueue.Len()
	require.NoError(t, lengthErr)
	assert.Equal(t, 1, queueLength, "吊销令牌下在途批次放回队列，证据零丢失")
	assert.Empty(t, quarantineNames(t, spoolQueue), "吊销不归档（区分于 400 类永久非法）")
	assert.Empty(t, reservedWorking(t, spoolQueue), "放回后无在途租约残留")
}

// reservedWorking 返回 working 在途目录中的租约文件名（不存在则视为空）。
func reservedWorking(t *testing.T, spoolQueue *spool.Spool) []string {
	t.Helper()
	return spoolDirNames(t, spoolQueue, "working")
}
