package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/internal/servetest"
)

// mustCreateAlertForWorker 直接落一条告警供 worker 外送测试使用。
func mustCreateAlertForWorker(t *testing.T, alertStore *store.Store, ruleID string, severity string) store.Alert {
	t.Helper()
	alertRow := &store.Alert{
		DeviceID: "dev-worker", SessionKey: "sess-worker", EventID: "evt-" + ruleID,
		RuleID: ruleID, RuleName: "规则-" + ruleID, Severity: severity, Action: "block",
		Snippet: "s", Summary: "sm",
	}
	require.NoError(t, alertStore.CreateAlert(context.Background(), alertRow))
	return *alertRow
}

// recordedRequest 记录一次收到的 POST。
type recordedRequest struct {
	body []byte
}

// newRecordingServer 建一个记录全部请求的收端，返回服务器与请求切片（mutex 保护）。
func newRecordingServer(handler func(requestWriter http.ResponseWriter, request *http.Request)) (*httptest.Server, *[]recordedRequest, *sync.Mutex) {
	var requestLog []recordedRequest
	var logMutex sync.Mutex
	receiveServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		bodyBytes, _ := io.ReadAll(request.Body)
		logMutex.Lock()
		requestLog = append(requestLog, recordedRequest{body: bodyBytes})
		logMutex.Unlock()
		if handler != nil {
			handler(responseWriter, request)
		} else {
			responseWriter.WriteHeader(http.StatusOK)
		}
	}))
	return receiveServer, &requestLog, &logMutex
}

func TestWorkerDeliversAggregatedDigest(t *testing.T) {
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts")
	alertStore := store.NewStore(testPool)

	receiveServer, requestLog, _ := newRecordingServer(nil)
	defer receiveServer.Close()

	worker := NewWorker(alertStore, NewWebhookChannel(receiveServer.URL, "generic", nil, nil),
		[]string{"medium", "high"}, nil)
	worker.batchSize = 50

	_ = mustCreateAlertForWorker(t, alertStore, "dlp.jwt", "high")
	_ = mustCreateAlertForWorker(t, alertStore, "cmd.rm_rf_root", "medium")

	require.NoError(t, worker.deliverBatch(context.Background(),
		mustListUnnotified(t, alertStore, 2)))

	require.Len(t, *requestLog, 1, "两条告警聚合成一次 POST")
	var payload struct {
		Text  string `json:"text"`
		Count int    `json:"count"`
	}
	require.NoError(t, json.Unmarshal((*requestLog)[0].body, &payload))
	assert.Equal(t, 2, payload.Count)
	assert.Contains(t, payload.Text, "【a3 告警】2 条新风险告警")

	remainingList, listErr := alertStore.ListUnnotifiedAlerts(context.Background(), []string{"medium", "high"}, 10, 100)
	require.NoError(t, listErr)
	assert.Empty(t, remainingList, "外送成功后不再捞出")
}

func TestWorkerRetriesThenRecovers(t *testing.T) {
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts")
	alertStore := store.NewStore(testPool)

	var failMode atomic.Bool
	receiveServer, requestLog, _ := newRecordingServer(func(requestWriter http.ResponseWriter, request *http.Request) {
		if failMode.Load() {
			http.Error(requestWriter, "down", http.StatusInternalServerError)
			return
		}
		requestWriter.WriteHeader(http.StatusOK)
	})
	defer receiveServer.Close()

	channel := NewWebhookChannel(receiveServer.URL, "generic", nil, nil)
	worker := NewWorker(alertStore, channel, []string{"medium", "high"}, nil)

	mustCreateAlertForWorker(t, alertStore, "dlp.jwt", "high")

	// 第一轮失败：收端 500 → attempts 累加、告警仍在待送集合
	failMode.Store(true)
	require.Error(t, worker.deliverBatch(context.Background(), mustListUnnotified(t, alertStore, 10)))
	afterFailList, listErr := alertStore.ListUnnotifiedAlerts(context.Background(), []string{"medium", "high"}, 10, 100)
	require.NoError(t, listErr)
	require.Len(t, afterFailList, 1)
	assert.Equal(t, 1, afterFailList[0].NotifyAttempts)

	// 第二轮恢复：收端 200 → 重发成功并标记
	failMode.Store(false)
	require.NoError(t, worker.deliverBatch(context.Background(), mustListUnnotified(t, alertStore, 10)))
	require.Len(t, *requestLog, 2)
	afterRecoverList, recoverListErr := alertStore.ListUnnotifiedAlerts(context.Background(), []string{"medium", "high"}, 10, 100)
	require.NoError(t, recoverListErr)
	assert.Empty(t, afterRecoverList)
}

func TestWorkerGivesUpAfterMaxAttempts(t *testing.T) {
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts")
	alertStore := store.NewStore(testPool)

	var requestCount atomic.Int64
	receiveServer, _, _ := newRecordingServer(func(requestWriter http.ResponseWriter, request *http.Request) {
		requestCount.Add(1)
		http.Error(requestWriter, "down", http.StatusInternalServerError)
	})
	defer receiveServer.Close()

	channel := NewWebhookChannel(receiveServer.URL, "generic", nil, nil)
	worker := NewWorker(alertStore, channel, []string{"medium", "high"}, nil)
	worker.maxAttempts = 2 // 收紧上限便于测试

	mustCreateAlertForWorker(t, alertStore, "dlp.jwt", "high")

	// 两轮失败后 attempts 达上限 2
	require.Error(t, worker.deliverBatch(context.Background(), mustListUnnotified(t, alertStore, 10)))
	require.Error(t, worker.deliverBatch(context.Background(), mustListUnnotified(t, alertStore, 10)))
	assert.EqualValues(t, 2, requestCount.Load())

	// 达上限后捞取为空：不再发送
	remainingList, listErr := alertStore.ListUnnotifiedAlerts(context.Background(), []string{"medium", "high"}, 2, 100)
	require.NoError(t, listErr)
	assert.Empty(t, remainingList)
	assert.False(t, worker.deliverPending(context.Background()), "attempts 耗尽后捞取为空，不发送也不置失败")
	assert.EqualValues(t, 2, requestCount.Load(), "attempts 耗尽后不再请求收端")
}

func TestWorkerSplitsByBatchSize(t *testing.T) {
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts")
	alertStore := store.NewStore(testPool)

	receiveServer, requestLog, logMutex := newRecordingServer(nil)
	defer receiveServer.Close()

	worker := NewWorker(alertStore, NewWebhookChannel(receiveServer.URL, "generic", nil, nil),
		[]string{"medium", "high"}, nil)
	worker.batchSize = 2

	for index := 0; index < 3; index++ {
		mustCreateAlertForWorker(t, alertStore, "rule"+string(rune('a'+index)), "high")
	}

	assert.False(t, worker.deliverPending(context.Background()))
	logMutex.Lock()
	require.Len(t, *requestLog, 2, "3 条 batchSize=2 分成 2 消息")
	var firstPayload, secondPayload struct {
		Count int `json:"count"`
	}
	require.NoError(t, json.Unmarshal((*requestLog)[0].body, &firstPayload))
	require.NoError(t, json.Unmarshal((*requestLog)[1].body, &secondPayload))
	logMutex.Unlock()
	assert.Equal(t, 2, firstPayload.Count)
	assert.Equal(t, 1, secondPayload.Count)
}

func TestWorkerBurstLimit(t *testing.T) {
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts")
	alertStore := store.NewStore(testPool)

	receiveServer, requestLog, logMutex := newRecordingServer(nil)
	defer receiveServer.Close()

	worker := NewWorker(alertStore, NewWebhookChannel(receiveServer.URL, "generic", nil, nil),
		[]string{"medium", "high"}, nil)
	worker.batchSize = 5
	worker.maxBatchBurst = 2

	for index := 0; index < 12; index++ {
		mustCreateAlertForWorker(t, alertStore, "rule"+string(rune('a'+index)), "high")
	}

	assert.False(t, worker.deliverPending(context.Background()))
	logMutex.Lock()
	assert.Len(t, *requestLog, 2, "12 条 batchSize=5 burst=2 单轮只发 2 批")
	logMutex.Unlock()

	// 余量留待下轮：12 - 2批×5 = 2 条仍在待送集合
	remainingList, listErr := alertStore.ListUnnotifiedAlerts(context.Background(), []string{"medium", "high"}, 10, 100)
	require.NoError(t, listErr)
	assert.Len(t, remainingList, 2)
}

func TestWorkerSeverityFilter(t *testing.T) {
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts")
	alertStore := store.NewStore(testPool)

	receiveServer, requestLog, logMutex := newRecordingServer(nil)
	defer receiveServer.Close()

	worker := NewWorker(alertStore, NewWebhookChannel(receiveServer.URL, "generic", nil, nil),
		[]string{"high"}, nil) // 只送 high

	mustCreateAlertForWorker(t, alertStore, "dlp.jwt", "high")
	mustCreateAlertForWorker(t, alertStore, "perf.copy_secret", "medium")
	mustCreateAlertForWorker(t, alertStore, "perf.copy_secret", "low")

	assert.False(t, worker.deliverPending(context.Background()))
	logMutex.Lock()
	require.Len(t, *requestLog, 1)
	var payload struct {
		Count int `json:"count"`
	}
	require.NoError(t, json.Unmarshal((*requestLog)[0].body, &payload))
	logMutex.Unlock()
	assert.Equal(t, 1, payload.Count, "只外送 high")
}

// mustListUnnotified 捞取待送告警（测试便捷封装）。
func mustListUnnotified(t *testing.T, alertStore *store.Store, limit int) []store.Alert {
	t.Helper()
	pendingAlerts, listErr := alertStore.ListUnnotifiedAlerts(context.Background(), []string{"medium", "high"}, 10, limit)
	require.NoError(t, listErr)
	require.NotEmpty(t, pendingAlerts)
	return pendingAlerts
}
