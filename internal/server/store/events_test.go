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

func TestUpdateEventRiskTags(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "events", "devices")
	eventStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, eventStore, "dev-ev-3")

	_, insertErr := eventStore.InsertEvents(ctx, []EventRow{{
		EventID: "evt-tag-1", DeviceID: "dev-ev-3", SessionKey: "sess-t", AgentType: "claude-code",
		EventType: "tool_call", OccurredAt: time.Now().UTC(),
		PayloadJSON: []byte(`{}`), RiskTagsJSON: []byte(`[]`),
	}})
	require.NoError(t, insertErr)

	updatedTags := []byte(`[{"code":"cmd.git_force_push","severity":"high"}]`)
	require.NoError(t, eventStore.UpdateEventRiskTags(ctx, "evt-tag-1", updatedTags))

	sessionEvents, listErr := eventStore.ListEventsBySession(ctx, "dev-ev-3", "sess-t")
	require.NoError(t, listErr)
	require.Len(t, sessionEvents, 1)
	assert.JSONEq(t, string(updatedTags), string(sessionEvents[0].RiskTagsJSON))

	updateErr := eventStore.UpdateEventRiskTags(ctx, "evt-missing", updatedTags)
	assert.ErrorIs(t, updateErr, ErrNotFound)
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
