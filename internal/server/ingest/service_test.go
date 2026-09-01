package ingest

import (
	"context"
	"errors"
	"sync"
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

// mustTestInstallCode 落一条可用安装凭据并返回明文代码（每次注册都会原子消费一次）。
func mustTestInstallCode(t *testing.T, testStore *store.Store, maxUses int) string {
	t.Helper()
	code, generateErr := auth.GenerateInstallCode()
	require.NoError(t, generateErr)
	_, createErr := testStore.CreateInstallCredentialWithAudit(context.Background(),
		auth.HashToken(code), "device", time.Now().Add(time.Hour), maxUses, "tester", "tester", nil)
	require.NoError(t, createErr)
	return code
}

// newTestService 构建接入真实库的接入服务，并带回一个可复用的安装凭据（高用量）。
func newTestService(t *testing.T) (*Service, *store.Store, string) {
	t.Helper()
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool,
		"alerts", "sessions", "events", "devices", "install_credentials", "install_credential_uses", "audit_log")
	eventStore := store.NewStore(testPool)
	installCode := mustTestInstallCode(t, eventStore, 1000)
	ingestService := NewService(eventStore, alert.NewService(eventStore))
	return ingestService, eventStore, installCode
}

func mustRegisteredDevice(t *testing.T, ingestService *Service, eventStore *store.Store,
	installCode string, fingerprint string) (*store.Device, string) {
	t.Helper()
	registerResult, registerErr := ingestService.RegisterDevice(context.Background(), RegisterInput{
		Hostname: "host-" + fingerprint, OS: "darwin", Arch: "amd64",
		MachineFingerprint: fingerprint, InstallCode: installCode,
	}, "", "10.0.0.1")
	require.NoError(t, registerErr)
	require.NotEmpty(t, registerResult.Token, "新注册必须下发明文 Token")

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

func TestRegisterDeviceDuplicateReusesIdentityWithoutRotation(t *testing.T) {
	ingestService, eventStore, installCode := newTestService(t)
	ctx := context.Background()

	firstResult, firstErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook-pro", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-abc-123", InstallCode: installCode}, "", "10.0.0.1")
	require.NoError(t, firstErr)
	assert.Regexp(t, `^a3d_[0-9a-f]{64}$`, firstResult.Token)

	// 无凭证的同指纹注册必须被拒（身份顶替防护）
	_, noCredentialErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "evil-host", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-abc-123", InstallCode: installCode}, "", "10.0.0.1")
	assert.ErrorIs(t, noCredentialErr, store.ErrCredentialRequired)

	// 凭证错误同样拒绝
	_, wrongCredentialErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "evil-host", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-abc-123", InstallCode: installCode}, "a3d_not-the-token", "10.0.0.1")
	assert.ErrorIs(t, wrongCredentialErr, store.ErrCredentialMismatch)

	// 携带既有 Token 凭证复用身份：设备不变、Token 不轮换（created=false 不下发新 Token）
	secondResult, secondErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook-pro", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-abc-123", InstallCode: installCode}, firstResult.Token, "10.0.0.1")
	require.NoError(t, secondErr)
	assert.Equal(t, firstResult.DeviceID, secondResult.DeviceID)
	assert.Empty(t, secondResult.Token, "复用身份不下发新 Token，终端保留既有 Token")

	// 原 Token 仍有效（不轮换的关键断言）且主机名未被覆盖
	fetched, fetchErr := eventStore.GetDeviceByTokenHash(ctx, auth.HashToken(firstResult.Token))
	require.NoError(t, fetchErr)
	assert.Equal(t, "macbook-pro", fetched.Hostname, "复用不覆盖既有身份信息")

	// 指纹为空/超长拒绝（字段校验）
	_, emptyErr := ingestService.RegisterDevice(ctx, RegisterInput{Hostname: "x", InstallCode: installCode}, "", "10.0.0.1")
	assert.True(t, errors.Is(emptyErr, ErrEventInvalid))
}

func TestRegisterDeviceRestoresRevokedDeviceWithoutCredential(t *testing.T) {
	ingestService, eventStore, installCode := newTestService(t)
	ctx := context.Background()

	firstResult, firstErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-recover-1", InstallCode: installCode}, "", "10.0.0.1")
	require.NoError(t, firstErr)
	require.NoError(t, eventStore.SetDeviceStatus(ctx, firstResult.DeviceID, "revoked"))

	// 令牌丢失后的恢复路径：管理员吊销后，携安装凭据重注册即可重建设备
	recoverResult, recoverErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-recover-1", InstallCode: installCode}, "", "10.0.0.1")
	require.NoError(t, recoverErr)
	assert.NotEqual(t, firstResult.DeviceID, recoverResult.DeviceID, "恢复必须重建设备，不复活吊销行")
	assert.NotEmpty(t, recoverResult.Token, "重建设备下发新 Token")

	revokedDevice, revokedFindErr := eventStore.GetDeviceByTokenHash(ctx, auth.HashToken(firstResult.Token))
	require.NoError(t, revokedFindErr)
	assert.Equal(t, "revoked", revokedDevice.Status, "吊销留痕必须保留")
	recoveredDevice, recoveredFindErr := eventStore.GetDeviceByTokenHash(ctx, auth.HashToken(recoverResult.Token))
	require.NoError(t, recoveredFindErr)
	assert.Equal(t, "active", recoveredDevice.Status)
	assert.Equal(t, "fp-recover-1", recoveredDevice.MachineFingerprint)

	// 重建后再注册：active 新行存在，凭证保护恢复生效，无凭证仍被拒
	_, noCredentialErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook", MachineFingerprint: "fp-recover-1", InstallCode: installCode}, "", "10.0.0.1")
	assert.ErrorIs(t, noCredentialErr, store.ErrCredentialRequired)
	// 携带新凭证：命中 active 新行，复用身份而非再建新行
	thirdResult, thirdErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-recover-1", InstallCode: installCode}, recoverResult.Token, "10.0.0.1")
	require.NoError(t, thirdErr)
	assert.Equal(t, recoverResult.DeviceID, thirdResult.DeviceID, "再次注册命中的应是新 active 行")
	assert.Empty(t, thirdResult.Token)
}

func TestRegisterDeviceRequiresInstallCredential(t *testing.T) {
	_, testStore, _ := newTestService(t) // 复用同一 schema；单独测凭据门禁
	ctx := context.Background()

	baseInput := RegisterInput{
		Hostname: "macbook", OS: "darwin", Arch: "arm64", MachineFingerprint: "fp-gate-1",
	}

	t.Run("缺代码", func(t *testing.T) {
		closedService := NewService(testStore, alert.NewService(testStore))
		_, registerErr := closedService.RegisterDevice(ctx, baseInput, "", "10.0.0.1")
		assert.ErrorIs(t, registerErr, ErrCredentialInvalid)
	})

	t.Run("格式不合法", func(t *testing.T) {
		closedService := NewService(testStore, alert.NewService(testStore))
		input := baseInput
		input.InstallCode = "not-a-valid-code"
		_, registerErr := closedService.RegisterDevice(ctx, input, "", "10.0.0.1")
		assert.ErrorIs(t, registerErr, ErrCredentialInvalid)
	})

	t.Run("代码无效（未入库）", func(t *testing.T) {
		closedService := NewService(testStore, alert.NewService(testStore))
		unknownCode, _ := auth.GenerateInstallCode()
		input := baseInput
		input.InstallCode = unknownCode
		_, registerErr := closedService.RegisterDevice(ctx, input, "", "10.0.0.1")
		assert.ErrorIs(t, registerErr, ErrCredentialUnknown)
	})

	t.Run("代码已过期 / 已停用 / 用量用尽", func(t *testing.T) {
		now := time.Now()

		expiredCode, _ := auth.GenerateInstallCode()
		_, _ = testStore.CreateInstallCredentialWithAudit(ctx,
			auth.HashToken(expiredCode), "device", now.Add(-time.Minute), 3, "tester", "tester", nil)

		disabledCode, _ := auth.GenerateInstallCode()
		disabledRow, _ := testStore.CreateInstallCredentialWithAudit(ctx,
			auth.HashToken(disabledCode), "device", now.Add(time.Hour), 3, "tester", "tester", nil)
		_ = testStore.RevokeInstallCredentialWithAudit(ctx, disabledRow.ID, "tester")

		oneShotCode := mustTestInstallCode(t, testStore, 1)

		// 先成功消费掉一次性代码的唯一用量（注册一台设备），随后再注册即用量用尽。
		// 配合下方「用量耗尽」用例顺位：该用例再携同一代码注册必须被拒。
		consumedService := NewService(testStore, alert.NewService(testStore))
		consumedResult, consumedErr := consumedService.RegisterDevice(ctx, RegisterInput{
			Hostname: "macbook", OS: "darwin", Arch: "arm64",
			MachineFingerprint: "fp-gate-oneshot", InstallCode: oneShotCode}, "", "10.0.0.2")
		require.NoError(t, consumedErr)
		require.NotEmpty(t, consumedResult.Token)

		cases := []struct {
			name         string
			code         string
			expectedErr  error
		}{
			{"过期", expiredCode, ErrCredentialExpired},
			{"停用", disabledCode, ErrCredentialDisabled},
			{"用量耗尽", oneShotCode, ErrCredentialUsedUp},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				closedService := NewService(testStore, alert.NewService(testStore))
				input := baseInput
				input.InstallCode = tc.code
				input.MachineFingerprint = "fp-gate-" + tc.name
				_, registerErr := closedService.RegisterDevice(ctx, input, "", "10.0.0.2")
				assert.ErrorIs(t, registerErr, tc.expectedErr)
			})
		}
	})
}

func TestRegisterConsumesInstallCodeOnce(t *testing.T) {
	ingestService, eventStore, _ := newTestService(t)
	ctx := context.Background()

	oneShotCode := mustTestInstallCode(t, eventStore, 1)
	firstResult, firstErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook-pro", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-oneshot-1", InstallCode: oneShotCode}, "", "10.0.0.9")
	require.NoError(t, firstErr)
	assert.NotEmpty(t, firstResult.Token)

	// 同一代码第二次使用 → 拒绝；设备只建了一台
	_, secondErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "macbook-pro", OS: "darwin", Arch: "arm64",
		MachineFingerprint: "fp-oneshot-1", InstallCode: oneShotCode}, firstResult.Token, "10.0.0.9")
	assert.ErrorIs(t, secondErr, ErrCredentialUsedUp, "一次性代码只能消费一次")

	devices, _ := eventStore.ListDevices(ctx)
	require.Len(t, devices, 1)

	// 使用记录：成功消费 + 拒绝事件均已留痕
	credentials, _ := eventStore.ListInstallCredentials(ctx)
	require.Len(t, credentials, 2) // newTestService 的高用量代码 + 本次一次性代码
	useRows, total, listErr := eventStore.ListCredentialUses(ctx, credentials[0].ID, 1, 10)
	require.NoError(t, listErr)
	assert.Equal(t, 2, total)
	assert.Equal(t, store.CredentialOutcomeRejectedUsed, useRows[0].Outcome, "最新一条是二次注册的拒绝事件")
	assert.Equal(t, store.CredentialOutcomeSuccess, useRows[1].Outcome) // 先前的一次性消费
}

func TestRegisterConcurrentConflictResolvesToOneDevice(t *testing.T) {
	ingestService, eventStore, installCode := newTestService(t)
	ctx := context.Background()

	const competitors = 8
	var successResults []*RegisterResult
	var mu sync.Mutex
	var waitGroup sync.WaitGroup

	for i := 0; i < competitors; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			result, registerErr := ingestService.RegisterDevice(ctx, RegisterInput{
				Hostname: "host", OS: "darwin", Arch: "amd64",
				MachineFingerprint: "fp-race-1", InstallCode: installCode}, "", "10.0.0.1")
			if registerErr != nil {
				assert.ErrorIs(t, registerErr, store.ErrCredentialRequired, "竞态输家应得到 409")
				return
			}
			mu.Lock()
			successResults = append(successResults, result)
			mu.Unlock()
		}()
		}
	waitGroup.Wait()

	require.Len(t, successResults, 1, "同指纹并发只允许一台注册成功")
	winner := successResults[0]
	assert.NotEmpty(t, winner.Token)

	// 冲突后重试：携胜者 Token 复用身份，不再产生第二台设备
	retryResult, retryErr := ingestService.RegisterDevice(ctx, RegisterInput{
		Hostname: "host", OS: "darwin", Arch: "amd64",
		MachineFingerprint: "fp-race-1", InstallCode: installCode}, winner.Token, "10.0.0.1")
	require.NoError(t, retryErr)
	assert.Equal(t, winner.DeviceID, retryResult.DeviceID)
	assert.Empty(t, retryResult.Token)

	devices, _ := eventStore.ListDevices(ctx)
	require.Len(t, devices, 1, "冲突重试不产生第二台设备")
}

func TestSubmitEventsHappyPathAndReplay(t *testing.T) {
	ingestService, eventStore, installCode := newTestService(t)
	ctx := context.Background()
	deviceRow, _ := mustRegisteredDevice(t, ingestService, eventStore, installCode, "fp-submit-1")

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

	sessionA, sessionAErr := eventStore.GetSession(ctx, deviceRow.DeviceID, "sess-a")
	require.NoError(t, sessionAErr)
	assert.Equal(t, 2, sessionA.EventCount)
	assert.Equal(t, "修复登录页面的报错", sessionA.Title)
	sessionB, sessionBErr := eventStore.GetSession(ctx, deviceRow.DeviceID, "sess-b")
	require.NoError(t, sessionBErr)
	assert.Equal(t, 1, sessionB.EventCount)

	fetchedDevice, fetchErr := eventStore.GetDeviceByTokenHash(ctx, deviceRow.TokenHash)
	require.NoError(t, fetchErr)
	assert.Equal(t, "1.0.0", fetchedDevice.AgentVersion)

	replayResult, replayErr := ingestService.SubmitEvents(ctx, deviceRow, envelope)
	require.NoError(t, replayErr)
	assert.Equal(t, 0, replayResult.Accepted)
	assert.Equal(t, 3, replayResult.Duplicates)

	sessionAAfterReplay, sessionAgainErr := eventStore.GetSession(ctx, deviceRow.DeviceID, "sess-a")
	require.NoError(t, sessionAgainErr)
	assert.Equal(t, 2, sessionAAfterReplay.EventCount, "重放不得重复累计会话事件数")
}

func TestSubmitEventsValidation(t *testing.T) {
	ingestService, eventStore, installCode := newTestService(t)
	ctx := context.Background()
	deviceRow, _ := mustRegisteredDevice(t, ingestService, eventStore, installCode, "fp-submit-2")

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