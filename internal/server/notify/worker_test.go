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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/internal/servetest"
)

// mustCreateAlertForWorker 直接落一条告警；CreateAlert 会与其同事务登记 outbox 通知。
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

// mustClaim 领取到期待投递的通知（severities 恒取 medium/high）。
func mustClaim(t *testing.T, alertStore *store.Store, maxAttempts int, limit int) []store.Notification {
	t.Helper()
	claimed, claimErr := alertStore.ClaimDueNotifications(
		context.Background(), []string{"medium", "high"}, maxAttempts, limit)
	require.NoError(t, claimErr)
	return claimed
}

// outboxRow 测试用 outbox 行快照（直查共享库，非公开 API）。
type outboxRow struct {
	id           string
	status       string
	attempts     int
	lastError    string
	nextAttemptAt time.Time
}

// listOutbox 按 created_at 升序返回全部 outbox 行。
func listOutbox(t *testing.T, testPool *pgxpool.Pool) []outboxRow {
	t.Helper()
	rows, queryErr := testPool.Query(context.Background(),
		`SELECT id, status, attempts, COALESCE(last_error, ''), next_attempt_at
		   FROM notification_outbox ORDER BY created_at ASC`)
	require.NoError(t, queryErr)
	defer rows.Close()
	var outbox []outboxRow
	for rows.Next() {
		var row outboxRow
		require.NoError(t, rows.Scan(&row.id, &row.status, &row.attempts, &row.lastError, &row.nextAttemptAt))
		outbox = append(outbox, row)
	}
	require.NoError(t, rows.Err())
	return outbox
}

// forceFailedDue 把 failed 行的退避到期时间拨回过去，模拟退避流逝以便立刻重试。
func forceFailedDue(t *testing.T, testPool *pgxpool.Pool) {
	t.Helper()
	_, execErr := testPool.Exec(context.Background(),
		`UPDATE notification_outbox SET next_attempt_at = now() - interval '1 second' WHERE status = 'failed'`)
	require.NoError(t, execErr)
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

	worker := NewWorker(alertStore, NewWebhookChannel(receiveServer.URL, "generic", plainHTTPClient(), nil),
		[]string{"medium", "high"}, nil)
	worker.batchSize = 50

	_ = mustCreateAlertForWorker(t, alertStore, "dlp.jwt", "high")
	_ = mustCreateAlertForWorker(t, alertStore, "cmd.rm_rf_root", "medium")

	require.NoError(t, worker.deliverBatch(context.Background(), mustClaim(t, alertStore, 10, 50)))

	require.Len(t, *requestLog, 1, "两条告警聚合成一次 POST")
	var payload struct {
		Text  string `json:"text"`
		Count int    `json:"count"`
	}
	require.NoError(t, json.Unmarshal((*requestLog)[0].body, &payload))
	assert.Equal(t, 2, payload.Count)
	assert.Contains(t, payload.Text, "【a3 告警】2 条新风险告警")

	outbox := listOutbox(t, testPool)
	require.Len(t, outbox, 2)
	for _, row := range outbox {
		assert.Equal(t, "sent", row.status)
		assert.Equal(t, 1, row.attempts)
	}

	assert.Empty(t, mustClaim(t, alertStore, 10, 50), "外送成功后不再捞出")
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

	channel := NewWebhookChannel(receiveServer.URL, "generic", plainHTTPClient(), nil)
	worker := NewWorker(alertStore, channel, []string{"medium", "high"}, nil)

	mustCreateAlertForWorker(t, alertStore, "dlp.jwt", "high")

	// 第一轮失败：收端 500 → 累计 attempts、置 failed 并退避
	failMode.Store(true)
	require.Error(t, worker.deliverBatch(context.Background(), mustClaim(t, alertStore, 10, 10)))
	afterFailOutbox := listOutbox(t, testPool)
	require.Len(t, afterFailOutbox, 1)
	assert.Equal(t, "failed", afterFailOutbox[0].status)
	assert.Equal(t, 1, afterFailOutbox[0].attempts)
	assert.Contains(t, afterFailOutbox[0].lastError, "500")
	assert.True(t, afterFailOutbox[0].nextAttemptAt.After(time.Now()), "失败后按退避推后下次尝试")
	assert.Empty(t, mustClaim(t, alertStore, 10, 10), "退避未到期的 failed 行不可领取")

	// 第二轮恢复：退避到期后重送成功并置 sent
	failMode.Store(false)
	forceFailedDue(t, testPool)
	require.NoError(t, worker.deliverBatch(context.Background(), mustClaim(t, alertStore, 10, 10)))
	require.Len(t, *requestLog, 2)

	recoveredOutbox := listOutbox(t, testPool)
	require.Len(t, recoveredOutbox, 1)
	assert.Equal(t, "sent", recoveredOutbox[0].status)
	assert.Equal(t, 2, recoveredOutbox[0].attempts)
	assert.Empty(t, mustClaim(t, alertStore, 10, 10))
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

	channel := NewWebhookChannel(receiveServer.URL, "generic", plainHTTPClient(), nil)
	worker := NewWorker(alertStore, channel, []string{"medium", "high"}, nil)
	worker.maxAttempts = 2 // 收紧上限便于测试

	mustCreateAlertForWorker(t, alertStore, "dlp.jwt", "high")

	// 两次失败后 attempts 达上限 → 置 dropped
	require.Error(t, worker.deliverBatch(context.Background(), mustClaim(t, alertStore, 2, 10)))
	forceFailedDue(t, testPool)
	require.Error(t, worker.deliverBatch(context.Background(), mustClaim(t, alertStore, 2, 10)))
	assert.EqualValues(t, 2, requestCount.Load())

	exhaustedOutbox := listOutbox(t, testPool)
	require.Len(t, exhaustedOutbox, 1)
	assert.Equal(t, "dropped", exhaustedOutbox[0].status)
	assert.Equal(t, 2, exhaustedOutbox[0].attempts)

	// attempts 达上限后不可再领取，不再请求收端
	assert.Empty(t, mustClaim(t, alertStore, 2, 10))
	worker.deliverPending(context.Background())
	assert.EqualValues(t, 2, requestCount.Load(), "dropped 后不再请求收端")
}

func TestWorkerDrainsBacklogInBatches(t *testing.T) {
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts")
	alertStore := store.NewStore(testPool)

	receiveServer, requestLog, logMutex := newRecordingServer(nil)
	defer receiveServer.Close()

	worker := NewWorker(alertStore, NewWebhookChannel(receiveServer.URL, "generic", plainHTTPClient(), nil),
		[]string{"medium", "high"}, nil)
	worker.batchSize = 2

	for index := 0; index < 3; index++ {
		mustCreateAlertForWorker(t, alertStore, "rule-"+time.Now().Format("150405000")+string(rune('a'+index)), "high")
	}

	worker.deliverPending(context.Background())
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

	outbox := listOutbox(t, testPool)
	require.Len(t, outbox, 3)
	for _, row := range outbox {
		assert.Equal(t, "sent", row.status)
	}
}

func TestNotifyBackoffExponential(t *testing.T) {
	testCases := []struct {
		attempt int
		expect  time.Duration
	}{
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{5, 15 * time.Minute}, // 封顶
		{10, 15 * time.Minute},
	}
	for _, testCase := range testCases {
		assert.Equal(t, testCase.expect, notifyBackoff(testCase.attempt, time.Minute, 15*time.Minute))
	}
}