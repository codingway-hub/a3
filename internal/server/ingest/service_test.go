package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/alert"
	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/internal/servetest"
	"github.com/codingway-hub/a3/pkg/schema"
)

// newTestService 构建接入真实库的接入服务（自动注册开启）。
func newTestService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts", "sessions", "events", "devices")
	eventStore := store.NewStore(testPool)
	ingestService := NewService(eventStore, alert.NewService(eventStore), true)
	return ingestService, eventStore
}

func mustRegisteredDevice(t *testing.T, ingestService *Service, eventStore *store.Store,
	fingerprint string) (*store.Device, string) {
	t.Helper()
	registerResult, registerErr := ingestService.RegisterDevice(context.Background(), RegisterInput{
		Hostname: "host-" + fingerprint, OS: "darwin", Arch: "amd64",
		MachineFingerprint: fingerprint,
	})
	require.NoError(t, registerErr)

	deviceRow, lookupErr := eventStore.GetDeviceByTokenHash(context.Background(),
		auth.HashToken(registerResult.Token))
	require.NoError(t, lookupErr)
	return deviceRow, registerResult.Token
}

func sampleConversationEvent(deviceID string, sessionKey string, eventID string, content string) schema.Event {
	return schema.Event{
		EventID: eventID, EventType: schema.EventTypeConversation, Role: "user",
		AgentType: schema.AgentTypeClaudeCode, SessionID: sessionKey, DeviceID: deviceID,
		OccurredAt: time.Now().UTC(), Content: content, SourceMethod: schema.SourceMethodFileLog,
	}
}

func TestRegisterDeviceIdempotentByFingerprint(t *testing.T) {
	ingestService, eventStore := newTestService(t)
	ctx := context.Background()

	firstResult, firstErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook-pro", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-abc-123"})
	require.NoError(t, firstErr)
	assert.NotEmpty(t, firstResult.DeviceID)
	assert.Regexp(t, `^a3d_[0-9a-f]{64}$`, firstResult.Token)

	// 同指纹再次注册：设备身份不变、Token 轮换
	secondResult, secondErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook-pro", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-abc-123"})
	require.NoError(t, secondErr)
	assert.Equal(t, firstResult.DeviceID, secondResult.DeviceID)
	assert.NotEqual(t, firstResult.Token, secondResult.Token)

	// 旧 Token 已失效，新 Token 可反查（库存的是 sha256 摘要，需先哈希再查）
	_, oldTokenErr := eventStore.GetDeviceByTokenHash(ctx, auth.HashToken(firstResult.Token))
	assert.ErrorIs(t, oldTokenErr, store.ErrNotFound)
	newDeviceRow, newTokenErr := eventStore.GetDeviceByTokenHash(ctx, auth.HashToken(secondResult.Token))
	require.NoError(t, newTokenErr)
	assert.Equal(t, "macbook-pro", newDeviceRow.Hostname)

	// 指纹为空拒绝
	_, emptyErr := ingestService.RegisterDevice(ctx, RegisterInput{Hostname: "x"})
	assert.True(t, errors.Is(emptyErr, ErrEventInvalid))
}

func TestRegisterDeviceDisabledWhenAutoRegisterOff(t *testing.T) {
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "devices")
	closedService := NewService(store.NewStore(testPool), nil, false)
	_, registerErr := closedService.RegisterDevice(context.Background(), RegisterInput{
		MachineFingerprint: "fp-any"})
	assert.ErrorIs(t, registerErr, ErrAutoRegisterDisabled)
}

func TestSubmitEventsHappyPathAndReplay(t *testing.T) {
	ingestService, eventStore := newTestService(t)
	ctx := context.Background()
	deviceRow, _ := mustRegisteredDevice(t, ingestService, eventStore, "fp-submit-1")

	envelope := BatchEnvelope{
		AgentVersion: "1.0.0",
		Plugins:      []string{"claude-code"},
		Events: []schema.Event{
			sampleConversationEvent(deviceRow.DeviceID, "sess-a", "evt-ing-1", "修复登录页面的报错"),
			sampleConversationEvent(deviceRow.DeviceID, "sess-a", "evt-ing-2", "继续排查"),
			sampleConversationEvent(deviceRow.DeviceID, "sess-b", "evt-ing-3", "写单元测试"),
		},
	}
	batchResult, submitErr := ingestService.SubmitEvents(ctx, deviceRow, envelope)
	require.NoError(t, submitErr)
	assert.Equal(t, 3, batchResult.Accepted)
	assert.Equal(t, 0, batchResult.Duplicates)

	// 会话聚合：两个会话行，计数与标题正确
	sessionA, sessionAErr := eventStore.GetSession(ctx, deviceRow.DeviceID, "sess-a")
	require.NoError(t, sessionAErr)
	assert.Equal(t, 2, sessionA.EventCount)
	assert.Equal(t, "修复登录页面的报错", sessionA.Title)
	sessionB, sessionBErr := eventStore.GetSession(ctx, deviceRow.DeviceID, "sess-b")
	require.NoError(t, sessionBErr)
	assert.Equal(t, 1, sessionB.EventCount)

	// 心跳已刷新版本
	fetchedDevice, fetchErr := eventStore.GetDeviceByTokenHash(ctx, deviceRow.TokenHash)
	require.NoError(t, fetchErr)
	assert.Equal(t, "1.0.0", fetchedDevice.AgentVersion)

	// 整批重放：全部去重，计数不再累加
	replayResult, replayErr := ingestService.SubmitEvents(ctx, deviceRow, envelope)
	require.NoError(t, replayErr)
	assert.Equal(t, 0, replayResult.Accepted)
	assert.Equal(t, 3, replayResult.Duplicates)

	sessionAAfterReplay, sessionAgainErr := eventStore.GetSession(ctx, deviceRow.DeviceID, "sess-a")
	require.NoError(t, sessionAgainErr)
	assert.Equal(t, 2, sessionAAfterReplay.EventCount, "重放不得重复累计会话事件数")
}

func TestSubmitEventsValidation(t *testing.T) {
	ingestService, eventStore := newTestService(t)
	ctx := context.Background()
	deviceRow, _ := mustRegisteredDevice(t, ingestService, eventStore, "fp-submit-2")

	t.Run("混入非法事件整批拒绝", func(t *testing.T) {
		badEnvelope := BatchEnvelope{Events: []schema.Event{
			sampleConversationEvent(deviceRow.DeviceID, "s", "evt-ok", "正常内容"),
			sampleConversationEvent(deviceRow.DeviceID, "s", "", "缺少 event_id"),
		}}
		_, submitErr := ingestService.SubmitEvents(ctx, deviceRow, badEnvelope)
		assert.True(t, errors.Is(submitErr, ErrEventInvalid))
	})

	t.Run("冒用他设备 ID 整批拒绝", func(t *testing.T) {
		spoofedEnvelope := BatchEnvelope{Events: []schema.Event{
			sampleConversationEvent("dev-spoofed", "s", "evt-spoof", "内容"),
		}}
		_, spoofErr := ingestService.SubmitEvents(ctx, deviceRow, spoofedEnvelope)
		assert.True(t, errors.Is(spoofErr, ErrEventInvalid))
		assert.Contains(t, spoofErr.Error(), "设备归属不符")
	})

	t.Run("空批次拒绝", func(t *testing.T) {
		_, emptyErr := ingestService.SubmitEvents(ctx, deviceRow, BatchEnvelope{})
		assert.True(t, errors.Is(emptyErr, ErrEventInvalid))
	})

	t.Run("超过单批上限拒绝", func(t *testing.T) {
		oversized := make([]schema.Event, maxBatchEvents+1)
		for oversizeIndex := range oversized {
			oversized[oversizeIndex] = sampleConversationEvent(
				deviceRow.DeviceID, "s", "evt-big-"+time.Now().Format("150405"), "内容")
		}
		_, bigErr := ingestService.SubmitEvents(ctx, deviceRow, BatchEnvelope{Events: oversized})
		assert.ErrorIs(t, bigErr, ErrBatchTooLarge)
	})
}
