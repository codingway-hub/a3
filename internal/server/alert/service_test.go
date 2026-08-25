package alert

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/internal/servetest"
	"github.com/codingway-hub/a3/pkg/schema"
)

// newTestService 构建接入真实库的告警服务并加载种子规则。
func newTestService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts", "sessions", "events", "devices")

	eventStore := store.NewStore(testPool)
	service := NewService(eventStore)
	require.NoError(t, service.ReloadRules(context.Background()))
	return service, eventStore
}

func mustConversationEvent(eventID string, content string) schema.Event {
	return schema.Event{
		EventID: eventID, EventType: schema.EventTypeConversation, Role: "user",
		AgentType: schema.AgentTypeClaudeCode, SessionID: "sess-alert-svc", DeviceID: "dev-alert-svc",
		OccurredAt: time.Now().UTC(), Content: content, SourceMethod: schema.SourceMethodFileLog,
	}
}

func TestServiceEndToEndTaggingAndAlerting(t *testing.T) {
	service, eventStore := newTestService(t)
	servetest.MustSeedDevice(t, eventStore, "dev-alert-svc")
	ctx := context.Background()

	// 先入库事件（与 ingest 主链路一致：先 InsertEvents 再异步扫描）
	riskyEvent := mustConversationEvent("evt-svc-1", "配置里的 AKIAIOSFODNN7EXAMPLE 帮我看看")
	safeEvent := mustConversationEvent("evt-svc-2", "帮我看看这个函数的边界条件")
	_, insertErr := eventStore.InsertEvents(ctx, []store.EventRow{
		toEventRow(riskyEvent), toEventRow(safeEvent),
	})
	require.NoError(t, insertErr)

	serviceCtx, cancelService := context.WithCancel(ctx)
	defer cancelService()
	go service.Run(serviceCtx)

	service.SubmitAsync(riskyEvent)
	service.SubmitAsync(safeEvent)

	// 轮询等待异步处理完成
	waitFor(t, func() bool {
		sessionEvents, listErr := eventStore.ListEventsBySession(ctx, "dev-alert-svc", "sess-alert-svc")
		if listErr != nil {
			return false
		}
		for _, row := range sessionEvents {
			if row.EventID == riskyEvent.EventID && string(row.RiskTagsJSON) != "[]" {
				return true
			}
		}
		return false
	})

	// 1) 风险标签已回写、安全事件保持空标签
	sessionEvents, listErr := eventStore.ListEventsBySession(ctx, "dev-alert-svc", "sess-alert-svc")
	require.NoError(t, listErr)
	tagsByID := map[string]string{}
	for _, row := range sessionEvents {
		tagsByID[row.EventID] = string(row.RiskTagsJSON)
	}
	assert.Contains(t, tagsByID[riskyEvent.EventID], "dlp.aws_access_key")
	assert.JSONEq(t, `[]`, tagsByID[safeEvent.EventID])

	// 2) 高危 block 规则落了告警
	alertList, alertTotal, listAlertsErr := eventStore.ListAlerts(ctx, store.AlertFilter{})
	require.NoError(t, listAlertsErr)
	require.Equal(t, 1, alertTotal)
	assert.Equal(t, "dlp.aws_access_key", alertList[0].RuleID)
	assert.Equal(t, "open", alertList[0].Status)
	assert.Contains(t, alertList[0].Summary, "命中风险规则")
	assert.NotContains(t, alertList[0].Snippet, "AKIAIOSFODNN7EXAMPLE", "摘要片段必须脱敏")

	// 3) 会话风险计数 +1
	fetchedSession, fetchErr := eventStore.GetSession(ctx, "dev-alert-svc", "sess-alert-svc")
	require.NoError(t, fetchErr)
	assert.Equal(t, 1, fetchedSession.RiskCount)

	// 4) 无失败/丢弃
	assert.Zero(t, service.FailedCount())
	assert.Zero(t, service.DroppedCount())
}

func TestReloadRulesDisablesMatching(t *testing.T) {
	service, eventStore := newTestService(t)
	ctx := context.Background()

	require.NoError(t, eventStore.SetRuleEnabled(ctx, "dlp.jwt", false))
	require.NoError(t, service.ReloadRules(ctx))

	jwtEvent := mustConversationEvent("evt-reload-1",
		"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlMzQ1")
	riskTags := service.currentEngine().Evaluate(jwtEvent)
	assert.Empty(t, riskTags, "停用规则重载后不应再命中")

	require.NoError(t, eventStore.SetRuleEnabled(ctx, "dlp.jwt", true))
	require.NoError(t, service.ReloadRules(ctx))
	riskTagsAfterEnable := service.currentEngine().Evaluate(jwtEvent)
	require.Len(t, riskTagsAfterEnable, 1)
	assert.Equal(t, "dlp.jwt", riskTagsAfterEnable[0].Code)
}

func TestSubmitAsyncDropsWhenQueueFull(t *testing.T) {
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "devices")
	eventStore := store.NewStore(testPool)
	service := NewService(eventStore) // 不启动 Run 消费者

	for dropIndex := 0; dropIndex < eventChannelBuffer; dropIndex++ {
		service.SubmitAsync(mustConversationEvent("evt-fill", "普通文本"))
	}
	service.SubmitAsync(mustConversationEvent("evt-overflow", "溢出事件"))

	assert.Equal(t, int64(1), service.DroppedCount(), "队列写满后应丢弃并计数")
}

// toEventRow 复用 store 的行模型做入库准备（与服务端 ingest 同构）。
func toEventRow(event schema.Event) store.EventRow {
	payloadJSON, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		panic(marshalErr)
	}
	return store.EventRow{
		EventID: event.EventID, DeviceID: event.DeviceID, SessionKey: event.SessionID,
		AgentType: event.AgentType, EventType: event.EventType, Role: event.Role,
		OccurredAt: event.OccurredAt, PayloadJSON: payloadJSON, RiskTagsJSON: []byte(`[]`),
	}
}

// waitFor 每 50ms 轮询条件直到满足或超时（异步链路断言辅助）。
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("等待条件超时（5s）")
}

// TestBackfillSweepRecoversUnscannedEvents 钉住无损语义：
// 只入库、从未投递实时队列的事件（队列满丢弃/重启丢队列的等价情形），
// 启动对账必须把它们捞回补扫——风险事件照常打标落告警。
func TestBackfillSweepRecoversUnscannedEvents(t *testing.T) {
	service, eventStore := newTestService(t)
	servetest.MustSeedDevice(t, eventStore, "dev-alert-svc")
	ctx := context.Background()

	// 只入库不投递：等价于 SubmitAsync 满丢弃或进程重启丢内存队列
	riskyEvent := mustConversationEvent("evt-backfill-1", "密钥是 AKIAIOSFODNN7EXAMPLE")
	safeEvent := riskyEvent
	safeEvent.EventID = "evt-backfill-2"
	safeEvent.Content = "普通对话内容"
	payloadRows := []store.EventRow{toEventRow(riskyEvent), toEventRow(safeEvent)}
	_, insertErr := eventStore.InsertEvents(ctx, payloadRows)
	require.NoError(t, insertErr)

	// 启动 Run：启动即对账，未投递事件应被补扫
	serviceCtx, cancelService := context.WithCancel(ctx)
	defer cancelService()
	go service.Run(serviceCtx)

	waitFor(t, func() bool {
		sessionEvents, listErr := eventStore.ListEventsBySession(ctx, "dev-alert-svc", "sess-alert-svc")
		if listErr != nil {
			return false
		}
		for _, row := range sessionEvents {
			if row.EventID == "evt-backfill-1" && string(row.RiskTagsJSON) != "[]" {
				return true
			}
		}
		return false
	})

	// 补扫结果断言
	sessionEvents, listErr := eventStore.ListEventsBySession(ctx, "dev-alert-svc", "sess-alert-svc")
	require.NoError(t, listErr)
	tagsByID := map[string]string{}
	for _, row := range sessionEvents {
		tagsByID[row.EventID] = string(row.RiskTagsJSON)
	}
	assert.Contains(t, tagsByID["evt-backfill-1"], "dlp.aws_access_key")
	assert.JSONEq(t, `[]`, tagsByID["evt-backfill-2"])
}
