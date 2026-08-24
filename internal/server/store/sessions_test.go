package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpsertSessionAggregation(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "sessions", "events", "devices")
	sessionStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, sessionStore, "dev-ss-1")

	firstAt := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
	require.NoError(t, sessionStore.UpsertSession(ctx, SessionUpdate{
		DeviceID: "dev-ss-1", SessionKey: "sess-key-1", AgentType: "claude-code",
		Title: "修复登录 bug", LastOccurredAt: firstAt,
		EventCountDelta: 3, RiskCountDelta: 1,
	}))

	secondAt := firstAt.Add(5 * time.Minute)
	require.NoError(t, sessionStore.UpsertSession(ctx, SessionUpdate{
		DeviceID: "dev-ss-1", SessionKey: "sess-key-1", AgentType: "claude-code",
		Title: "", LastOccurredAt: secondAt.Add(-10 * time.Minute), // 早于已有 ended_at
		EventCountDelta: 2, RiskCountDelta: 0,
	}))

	fetched, fetchErr := sessionStore.GetSession(ctx, "dev-ss-1", "sess-key-1")
	require.NoError(t, fetchErr)
	assert.Equal(t, 5, fetched.EventCount, "event_count 应累加")
	assert.Equal(t, 1, fetched.RiskCount)
	assert.Equal(t, "修复登录 bug", fetched.Title)
	assert.True(t, firstAt.Equal(fetched.StartedAt), "started_at 应等于首个事件时间（忽略时区表示）")
	assert.True(t, firstAt.Equal(fetched.EndedAt), "更早的事件不得回退 ended_at（GREATEST 保持最大值）")

	// 更晚的事件推进 ended_at
	require.NoError(t, sessionStore.UpsertSession(ctx, SessionUpdate{
		DeviceID: "dev-ss-1", SessionKey: "sess-key-1", AgentType: "claude-code",
		Title: "", LastOccurredAt: secondAt,
		EventCountDelta: 1,
	}))
	advancedSession, advanceFetchErr := sessionStore.GetSession(ctx, "dev-ss-1", "sess-key-1")
	require.NoError(t, advanceFetchErr)
	assert.True(t, secondAt.Equal(advancedSession.EndedAt), "更晚事件应把 ended_at 推进到最新时间")

	// title 空的会话：首个非空标题补写，之后不再覆盖
	require.NoError(t, sessionStore.UpsertSession(ctx, SessionUpdate{
		DeviceID: "dev-ss-1", SessionKey: "sess-empty", AgentType: "claude-code",
		Title: "", LastOccurredAt: firstAt, EventCountDelta: 1,
	}))
	require.NoError(t, sessionStore.UpsertSession(ctx, SessionUpdate{
		DeviceID: "dev-ss-1", SessionKey: "sess-empty", AgentType: "claude-code",
		Title: "第一条非空标题", LastOccurredAt: secondAt, EventCountDelta: 1,
	}))
	require.NoError(t, sessionStore.UpsertSession(ctx, SessionUpdate{
		DeviceID: "dev-ss-1", SessionKey: "sess-empty", AgentType: "claude-code",
		Title: "更晚的标题不应覆盖", LastOccurredAt: secondAt, EventCountDelta: 1,
	}))
	emptyTitled, fetchEmptyErr := sessionStore.GetSession(ctx, "dev-ss-1", "sess-empty")
	require.NoError(t, fetchEmptyErr)
	assert.Equal(t, "第一条非空标题", emptyTitled.Title)

	_, missErr := sessionStore.GetSession(ctx, "dev-ss-1", "sess-missing")
	assert.ErrorIs(t, missErr, ErrNotFound)
}

func TestListSessionsFiltersAndPagination(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "sessions", "events", "devices")
	sessionStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, sessionStore, "dev-filter-a")
	mustSeedDevice(t, sessionStore, "dev-filter-b")

	baseTime := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	seeds := []struct {
		deviceID   string
		sessionKey string
		title      string
		risky      bool
		startedAt  time.Time
	}{
		{"dev-filter-a", "kw-match-1", "部署生产服务", false, baseTime},
		{"dev-filter-a", "kw-miss", "重构缓存层", true, baseTime.Add(1 * time.Hour)},
		{"dev-filter-b", "kw-match-2", "排查告警", true, baseTime.Add(2 * time.Hour)},
		{"dev-filter-b", "plain", "日常开发", false, baseTime.Add(-24 * time.Hour)},
	}
	for _, seed := range seeds {
		riskDelta := 0
		if seed.risky {
			riskDelta = 1
		}
		require.NoError(t, sessionStore.UpsertSession(ctx, SessionUpdate{
			DeviceID: seed.deviceID, SessionKey: seed.sessionKey, AgentType: "claude-code",
			Title: seed.title, LastOccurredAt: seed.startedAt,
			EventCountDelta: 1, RiskCountDelta: riskDelta,
		}))
	}

	// 关键词过滤（title 与 session_key 双列）
	keywordList, keywordTotal, kwErr := sessionStore.ListSessions(ctx, SessionFilter{Keyword: "kw-match"})
	require.NoError(t, kwErr)
	assert.Equal(t, 2, keywordTotal)
	require.Len(t, keywordList, 2)
	assert.Equal(t, "dev-filter-b", keywordList[0].DeviceID, "started_at 倒序：最晚开始的排前")

	// 设备过滤
	deviceList, deviceTotal, devErr := sessionStore.ListSessions(ctx, SessionFilter{DeviceID: "dev-filter-a"})
	require.NoError(t, devErr)
	assert.Equal(t, 2, deviceTotal)
	assert.Len(t, deviceList, 2)

	// 仅看风险
	riskList, riskTotal, riskErr := sessionStore.ListSessions(ctx, SessionFilter{RiskOnly: true})
	require.NoError(t, riskErr)
	assert.Equal(t, 2, riskTotal)
	for _, riskySession := range riskList {
		assert.Positive(t, riskySession.RiskCount)
	}

	// 时间范围
	from := baseTime
	to := baseTime.Add(90 * time.Minute)
	_, timeTotal, timeErr := sessionStore.ListSessions(ctx, SessionFilter{StartedFrom: &from, StartedTo: &to})
	require.NoError(t, timeErr)
	assert.Equal(t, 2, timeTotal)

	// 分页 + total
	pageOne, allTotal, pageErr := sessionStore.ListSessions(ctx, SessionFilter{Page: 1, PageSize: 3})
	require.NoError(t, pageErr)
	assert.Equal(t, 4, allTotal)
	assert.Len(t, pageOne, 3)
	pageTwo, _, secondPageErr := sessionStore.ListSessions(ctx, SessionFilter{Page: 2, PageSize: 3})
	require.NoError(t, secondPageErr)
	assert.Len(t, pageTwo, 1)
}

func TestCountSessionsOverview(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "sessions", "events", "devices")
	sessionStore := NewStore(testPool)
	ctx := context.Background()
	mustSeedDevice(t, sessionStore, "dev-count-1")

	now := time.Now().UTC()
	require.NoError(t, sessionStore.UpsertSession(ctx, SessionUpdate{
		DeviceID: "dev-count-1", SessionKey: "safe", AgentType: "claude-code",
		Title: "安全会话", LastOccurredAt: now, EventCountDelta: 1,
	}))
	require.NoError(t, sessionStore.UpsertSession(ctx, SessionUpdate{
		DeviceID: "dev-count-1", SessionKey: "risky", AgentType: "claude-code",
		Title: "风险会话", LastOccurredAt: now, EventCountDelta: 1, RiskCountDelta: 2,
	}))

	total, risky, countErr := sessionStore.CountSessions(ctx)
	require.NoError(t, countErr)
	assert.Equal(t, 2, total)
	assert.Equal(t, 1, risky)
}
