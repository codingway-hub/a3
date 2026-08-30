package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustSeedDevice 为事件/会话类用例准备外键依赖的设备行。
func mustSeedDevice(t *testing.T, deviceStore *Store, deviceID string) {
	t.Helper()
	createErr := deviceStore.CreateDevice(context.Background(),
		&Device{DeviceID: deviceID, TokenHash: "hash-" + deviceID, Hostname: "host-" + deviceID})
	require.NoError(t, createErr)
}

func TestInsertEventsIdempotent(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "events", "devices")
	eventStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, eventStore, "dev-ev-1")

	occurredAt := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	firstBatch := []EventRow{
		{EventID: "evt-001", DeviceID: "dev-ev-1", SessionKey: "sess-a", AgentType: "claude-code",
			EventType: "conversation", Role: "user", OccurredAt: occurredAt,
			PayloadJSON: []byte(`{"content":"你好"}`), RiskTagsJSON: []byte(`[]`)},
		{EventID: "evt-002", DeviceID: "dev-ev-1", SessionKey: "sess-a", AgentType: "claude-code",
			EventType: "tool_call", OccurredAt: occurredAt.Add(time.Second),
			PayloadJSON: []byte(`{"tool_name":"Bash"}`), RiskTagsJSON: []byte(`[]`)},
	}

	acceptedFlags, insertErr := eventStore.InsertEvents(ctx, firstBatch)
	require.NoError(t, insertErr)
	assert.Equal(t, []bool{true, true}, acceptedFlags)

	// 同一批乱序重放：全部冲突，无新增
	replay := []EventRow{firstBatch[1], firstBatch[0]}
	replayFlags, replayErr := eventStore.InsertEvents(ctx, replay)
	require.NoError(t, replayErr)
	assert.Equal(t, []bool{false, false}, replayFlags, "重复 event_id 不应计入 accepted")

	// 混合批次：重复事件穿插新事件，标记按位对齐
	mixed := append(replay, EventRow{EventID: "evt-003", DeviceID: "dev-ev-1", SessionKey: "sess-a",
		AgentType: "claude-code", EventType: "tool_result", OccurredAt: occurredAt.Add(2 * time.Second),
		PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)})
	mixedFlags, mixedErr := eventStore.InsertEvents(ctx, mixed)
	require.NoError(t, mixedErr)
	assert.Equal(t, []bool{false, false, true}, mixedFlags)
}

func TestListEventsBySessionOrderedAndIsolated(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "events", "devices")
	eventStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, eventStore, "dev-ev-2")

	baseTime := time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)
	rows := []EventRow{
		{EventID: "evt-b", DeviceID: "dev-ev-2", SessionKey: "sess-x", AgentType: "claude-code",
			EventType: "tool_call", OccurredAt: baseTime.Add(time.Second), PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
		{EventID: "evt-a", DeviceID: "dev-ev-2", SessionKey: "sess-x", AgentType: "claude-code",
			EventType: "conversation", Role: "user", OccurredAt: baseTime, PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
		{EventID: "evt-c", DeviceID: "dev-ev-2", SessionKey: "sess-y", AgentType: "claude-code",
			EventType: "session_start", OccurredAt: baseTime, PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
	}
	_, insertErr := eventStore.InsertEvents(ctx, rows)
	require.NoError(t, insertErr)

	sessionEvents, listErr := eventStore.ListEventsBySession(ctx, "dev-ev-2", "sess-x")
	require.NoError(t, listErr)
	require.Len(t, sessionEvents, 2)
	assert.Equal(t, "evt-a", sessionEvents[0].EventID, "应按 occurred_at 升序")
	assert.Equal(t, "evt-b", sessionEvents[1].EventID)
}

func TestApplyScanOutcomeAtomicAndOnceOnly(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts", "sessions", "events", "devices")
	eventStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, eventStore, "dev-ev-3")

	_, insertErr := eventStore.InsertEvents(ctx, []EventRow{{
		EventID: "evt-tag-1", DeviceID: "dev-ev-3", SessionKey: "sess-t", AgentType: "claude-code",
		EventType: "tool_call", OccurredAt: time.Now().UTC(),
		PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`),
	}})
	require.NoError(t, insertErr)

	outcomeAlerts := []*Alert{{
		DeviceID: "dev-ev-3", SessionKey: "sess-t", EventID: "evt-tag-1",
		RuleID: "dlp.jwt", RuleName: "JWT 令牌泄露", Severity: "high", Action: "block",
	}}
	applied, applyErr := eventStore.ApplyScanOutcome(ctx, ScanOutcome{
			DeviceID:     "dev-ev-3",
			EventID:      "evt-tag-1",
		RiskTagsJSON: []byte(`[{"code":"dlp.jwt","severity":"high"}]`),
		Alerts:       outcomeAlerts,
		SessionUpdate: SessionUpdate{
			DeviceID: "dev-ev-3", SessionKey: "sess-t", AgentType: "claude-code",
			LastOccurredAt: time.Now().UTC(), RiskCountDelta: 1,
		},
	})
	require.NoError(t, applyErr)
	assert.True(t, applied)

	// 重复应用（模拟实时链路与补扫竞速）：整体放弃，告警不翻倍
	reapplied, reapplyErr := eventStore.ApplyScanOutcome(ctx, ScanOutcome{
			DeviceID:     "dev-ev-3",
			EventID:      "evt-tag-1",
		RiskTagsJSON: []byte(`[{"code":"dlp.jwt","severity":"high"}]`),
		Alerts:       outcomeAlerts,
		SessionUpdate: SessionUpdate{
			DeviceID: "dev-ev-3", SessionKey: "sess-t", AgentType: "claude-code",
			LastOccurredAt: time.Now().UTC(), RiskCountDelta: 1,
		},
	})
	require.NoError(t, reapplyErr)
	assert.False(t, reapplied, "已扫描事件不应被二次应用")

	sessionEvents, listErr := eventStore.ListEventsBySession(ctx, "dev-ev-3", "sess-t")
	require.NoError(t, listErr)
	require.Len(t, sessionEvents, 1)
	assert.Contains(t, string(sessionEvents[0].RiskTagsJSON), "dlp.jwt")

	fetchedSession, fetchErr := eventStore.GetSession(ctx, "dev-ev-3", "sess-t")
	require.NoError(t, fetchErr)
	assert.Equal(t, 1, fetchedSession.RiskCount, "竞速失败方不得重复累计风险计数")

	alertList, alertTotal, listErr := eventStore.ListAlerts(ctx, AlertFilter{})
	require.NoError(t, listErr)
	assert.Equal(t, 1, alertTotal, "竞速失败方不得重复落告警")
	_ = alertList
}

func TestListUnscannedEventsOrderedAndMarkedAfterScan(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts", "sessions", "events", "devices")
	eventStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, eventStore, "dev-ev-5")

	baseTime := time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)
	_, insertErr := eventStore.InsertEvents(ctx, []EventRow{
		{EventID: "evt-u2", DeviceID: "dev-ev-5", SessionKey: "sess-u", AgentType: "claude-code",
			EventType: "tool_call", OccurredAt: baseTime.Add(time.Second),
			PayloadJSON: []byte(`{"event_id":"evt-u2"}`), RiskTagsJSON: []byte(`[]`)},
		{EventID: "evt-u1", DeviceID: "dev-ev-5", SessionKey: "sess-u", AgentType: "claude-code",
			EventType: "conversation", OccurredAt: baseTime,
			PayloadJSON: []byte(`{"event_id":"evt-u1"}`), RiskTagsJSON: []byte(`[]`)},
	})
	require.NoError(t, insertErr)

	unscannedRows, listErr := eventStore.ListUnscannedEvents(ctx, 10)
	require.NoError(t, listErr)
	require.Len(t, unscannedRows, 2)
	assert.Equal(t, []string{"evt-u1", "evt-u2"}, []string{
		unscannedRows[0].EventID, unscannedRows[1].EventID}, "应按发生时间升序捞出未扫描事件")

	// 扫描后不再出现在对账列表中
	_, applyErr := eventStore.ApplyScanOutcome(ctx, ScanOutcome{
			DeviceID:     "dev-ev-5",
			EventID:      "evt-u1",
		RiskTagsJSON: []byte(`[]`),
		SessionUpdate: SessionUpdate{
			DeviceID: "dev-ev-5", SessionKey: "sess-u", AgentType: "claude-code",
			LastOccurredAt: baseTime,
		},
	})
	require.NoError(t, applyErr)

	unscannedAfterScan, afterErr := eventStore.ListUnscannedEvents(ctx, 10)
	require.NoError(t, afterErr)
	require.Len(t, unscannedAfterScan, 1)
	assert.Equal(t, "evt-u2", unscannedAfterScan[0].EventID)
}

func TestCountEventsSince(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "events", "devices")
	eventStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, eventStore, "dev-ev-4")

	baseTime := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)
	rows := []EventRow{
		{EventID: "evt-s1", DeviceID: "dev-ev-4", SessionKey: "s", AgentType: "claude-code",
			EventType: "conversation", OccurredAt: baseTime.Add(1 * time.Hour), PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
		{EventID: "evt-s2", DeviceID: "dev-ev-4", SessionKey: "s", AgentType: "claude-code",
			EventType: "conversation", OccurredAt: baseTime.Add(2 * time.Hour), PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
		{EventID: "evt-old", DeviceID: "dev-ev-4", SessionKey: "s", AgentType: "claude-code",
			EventType: "conversation", OccurredAt: baseTime.Add(-24 * time.Hour), PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
	}
	_, insertErr := eventStore.InsertEvents(ctx, rows)
	require.NoError(t, insertErr)

	count, countErr := eventStore.CountEventsSince(ctx, baseTime)
	require.NoError(t, countErr)
	assert.Equal(t, 2, count, "仅统计 since 之后的事件")
}

// TestInsertEventBatchAndAggregateSessionsCrossDeviceAndAtomic 复合键原子性回归：
// 跨设备同 event_id 双落库、设备内重放幂等、会话聚合失败整批回滚。
func TestInsertEventBatchAndAggregateSessionsCrossDeviceAndAtomic(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts", "sessions", "events", "devices")
	eventStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, eventStore, "dev-cc-a")
	mustSeedDevice(t, eventStore, "dev-cc-b")

	baseTime := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	// 关键场景：两台设备各自上报同一个 event_id（终端确定性派生），复合键下互不吞并
	sharedID := "evt-shared-collision"
	crossDeviceRows := []EventRow{
		{EventID: sharedID, DeviceID: "dev-cc-a", SessionKey: "sess-a", AgentType: "claude-code",
			EventType: "tool_call", OccurredAt: baseTime, PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
		{EventID: sharedID, DeviceID: "dev-cc-b", SessionKey: "sess-b", AgentType: "claude-code",
			EventType: "tool_call", OccurredAt: baseTime, PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
	}
	acceptedFlags, insertErr := eventStore.InsertEventBatchAndAggregateSessions(ctx, crossDeviceRows,
		[]SessionUpdate{})
	require.NoError(t, insertErr)
	assert.Equal(t, []bool{true, true}, acceptedFlags, "跨设备同 event_id 必须双落库，证据无损")

	// 设备内重放同 event_id：幂等去重
	replayFlags, replayErr := eventStore.InsertEventBatchAndAggregateSessions(ctx, crossDeviceRows,
		[]SessionUpdate{})
	require.NoError(t, replayErr)
	assert.Equal(t, []bool{false, false}, replayFlags)

	sessionAEvents, _ := eventStore.ListEventsBySession(ctx, "dev-cc-a", "sess-a")
	sessionBEvents, _ := eventStore.ListEventsBySession(ctx, "dev-cc-b", "sess-b")
	assert.Len(t, sessionAEvents, 1, "A 设备证据独立存在")
	assert.Len(t, sessionBEvents, 1, "B 设备证据独立存在（复合键修复后不被吞并）")
	assert.Equal(t, sharedID, sessionAEvents[0].EventID)
	assert.Equal(t, sharedID, sessionBEvents[0].EventID)

	// 整批回滚：会话聚合/插入任一失败不得残留半批事件
	// 造 FK 违约：事件行与会话元都指向不存在的设备
	missingDeviceRows := []EventRow{{
		EventID: "evt-orphan", DeviceID: "dev-no-such", SessionKey: "sess-o", AgentType: "claude-code",
		EventType: "conversation", OccurredAt: baseTime, PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`),
	}}
	orphanMetas := []SessionUpdate{{
		DeviceID: "dev-no-such", SessionKey: "sess-o", AgentType: "claude-code",
		LastOccurredAt: baseTime,
	}}
	_, orphanErr := eventStore.InsertEventBatchAndAggregateSessions(ctx, missingDeviceRows, orphanMetas)
	require.Error(t, orphanErr, "不存在设备的插入必须整批失败")
	orphanEvents, _ := eventStore.ListEventsBySession(ctx, "dev-no-such", "sess-o")
	assert.Empty(t, orphanEvents, "失败事务不得残留事件（原子性）")
}

// TestRebuildSessionEventCountsPrecision 启动对账回归：
// 全量精算 event_count、保留标题与风险计数、时间窗取最值。
func TestRebuildSessionEventCountsPrecision(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "alerts", "sessions", "events", "devices")
	eventStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, eventStore, "dev-rb-1")

	early := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
	late := early.Add(2 * time.Hour)
	rows := []EventRow{
		{EventID: "evt-rb-1", DeviceID: "dev-rb-1", SessionKey: "sess-x", AgentType: "claude-code",
			EventType: "conversation", OccurredAt: early, PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
		{EventID: "evt-rb-2", DeviceID: "dev-rb-1", SessionKey: "sess-x", AgentType: "claude-code",
			EventType: "tool_call", OccurredAt: early.Add(time.Hour), PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
		{EventID: "evt-rb-3", DeviceID: "dev-rb-1", SessionKey: "sess-y", AgentType: "claude-code",
			EventType: "conversation", OccurredAt: late, PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`)},
	}
	_, insertErr := eventStore.InsertEvents(ctx, rows)
	require.NoError(t, insertErr)

	// 制造漂移：先写入错误的高计数会话与手工标题（模拟历史计数补充失败留下的残值）
	require.NoError(t, eventStore.UpsertSession(ctx, SessionUpdate{
		DeviceID: "dev-rb-1", SessionKey: "sess-x", AgentType: "claude-code",
		Title: "手工保留标题", LastOccurredAt: early, EventCountDelta: 99, RiskCountDelta: 3,
	}))

	require.NoError(t, eventStore.RebuildSessionEventCounts(ctx))

	sessionX, fetchErr := eventStore.GetSession(ctx, "dev-rb-1", "sess-x")
	require.NoError(t, fetchErr)
	assert.Equal(t, 2, sessionX.EventCount, "对账应精确重算为真实事件数")
	assert.Equal(t, "手工保留标题", sessionX.Title, "对账不得覆盖标题")
	assert.Equal(t, 3, sessionX.RiskCount, "对账不得覆盖风险计数（扫描链路独立累计）")
	assert.True(t, sessionX.StartedAt.Equal(early) || sessionX.StartedAt.Before(early),
		"会话起点不得晚于最早事件")

	sessionY, fetchYErr := eventStore.GetSession(ctx, "dev-rb-1", "sess-y")
	require.NoError(t, fetchYErr)
	assert.Equal(t, 1, sessionY.EventCount, "对账应补齐缺漏会话")
}
