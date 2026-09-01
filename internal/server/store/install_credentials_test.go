package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hashInstallCode 与生产 auth.HashToken 同格式（SHA-256 hex）；store 测试不
// 得 import auth（auth→store 依赖环），故内联一份等价实现。
func hashInstallCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// randomInstallCode 生成与生产同格式的测试用明文代码（任意唯一串即可，
// store 层不校验前缀）。
func randomInstallCode() string {
	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	return "a3i_" + hex.EncodeToString(randomBytes)
}

// mustSeedCredential 落一条可用的安装凭据并返回明文代码与凭据 ID（测试公用夹具）。
func mustSeedCredential(t *testing.T, testStore *Store, maxUses int) (string, int64) {
	t.Helper()
	code := randomInstallCode()
	credential, createErr := testStore.CreateInstallCredentialWithAudit(context.Background(),
		hashInstallCode(code), "device", time.Now().Add(24*time.Hour), maxUses,
		"test-admin", "test-admin", []byte(`{"scope":"device"}`))
	require.NoError(t, createErr)
	return code, credential.ID
}

// newCredentialStore 清空凭据两表与审计/设备表后的 Store（测试公用夹具）。
func newCredentialStore(t *testing.T) *Store {
	t.Helper()
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool,
		"install_credentials", "install_credential_uses", "audit_log", "devices")
	return NewStore(testPool)
}

func TestCredentialCreateListRevokeAudit(t *testing.T) {
	credentialStore := newCredentialStore(t)
	ctx := context.Background()
	now := time.Now()

	firstCode:= randomInstallCode()
	first, createErr := credentialStore.CreateInstallCredentialWithAudit(ctx,
		hashInstallCode(firstCode), "device", now.Add(time.Hour), 3, "admin-a", "admin-a",
		[]byte(`{"scope":"device"}`))
	require.NoError(t, createErr)
	assert.Equal(t, "device", first.Scope)
	assert.Equal(t, 3, first.MaxUses)
	assert.True(t, first.Enabled)
	assert.Len(t, first.CodeHint, 8, "列表只暴露摘要前缀")

	secondCode:= randomInstallCode()
	second, createErr := credentialStore.CreateInstallCredentialWithAudit(ctx,
		hashInstallCode(secondCode), "device", now.Add(time.Hour), 1, "admin-a", "admin-a",
		[]byte(`{"scope":"device"}`))
	require.NoError(t, createErr)
	assert.NotEqual(t, first.ID, second.ID)

	// 列表按生成倒序，且不含明文/完整哈希
	credentialList, listErr := credentialStore.ListInstallCredentials(ctx)
	require.NoError(t, listErr)
	require.Len(t, credentialList, 2)
	assert.Equal(t, second.ID, credentialList[0].ID, "最新的凭据排最前")

	// 吊销 + 审计留痕；重复吊销幂等返回 ErrNotFound
	require.NoError(t, credentialStore.RevokeInstallCredentialWithAudit(ctx, first.ID, "admin-a"))
	revokeAgainErr := credentialStore.RevokeInstallCredentialWithAudit(ctx, first.ID, "admin-a")
	assert.ErrorIs(t, revokeAgainErr, ErrNotFound, "已停用凭据再吊销应 ErrNotFound（不重复留痕）")

	auditEntries, auditTotal, auditErr := credentialStore.ListAuditLog(ctx, AuditFilter{TargetType: "credential"})
	require.NoError(t, auditErr)
	assert.Equal(t, 3, auditTotal, "credential_create×2 + credential_revoke×1")
	require.Len(t, auditEntries, 3)
	actions := map[string]bool{}
	for _, entry := range auditEntries {
		actions[entry.Action] = true
	}
	assert.True(t, actions[AuditActionCredentialCreate])
	assert.True(t, actions[AuditActionCredentialRevoke])
}

func TestConsumeCredentialSuccessThenUsedUp(t *testing.T) {
	credentialStore := newCredentialStore(t)
	ctx := context.Background()

	code, credentialID := mustSeedCredential(t, credentialStore, 2)
	codeHash := hashInstallCode(code)

	firstUseID, firstOutcome, firstErr := credentialStore.ConsumeInstallCredential(ctx, codeHash, "10.0.0.1")
	require.NoError(t, firstErr)
	assert.Equal(t, CredentialOutcomeSuccess, firstOutcome)
	assert.NotZero(t, firstUseID)

	_, secondOutcome, secondErr := credentialStore.ConsumeInstallCredential(ctx, codeHash, "10.0.0.2")
	require.NoError(t, secondErr)
	assert.Equal(t, CredentialOutcomeSuccess, secondOutcome)

	_, usedUpOutcome, usedUpErr := credentialStore.ConsumeInstallCredential(ctx, codeHash, "10.0.0.1")
	require.NoError(t, usedUpErr)
	assert.Equal(t, CredentialOutcomeRejectedUsed, usedUpOutcome, "用量耗尽应分类为 rejected_used")

	// 用量只对成功消费递增；成功与拒绝均留有使用记录
	credentialList, _ := credentialStore.ListInstallCredentials(ctx)
	require.Len(t, credentialList, 1)
	assert.Equal(t, 2, credentialList[0].UsesCount, "成功消费才递增用量，拒绝不递增")

	allUseRows, total, listErr := credentialStore.ListCredentialUses(ctx, credentialID, 1, 10)
	require.NoError(t, listErr)
	assert.Equal(t, 3, total, "两次成功 + 一次拒绝均有使用记录")
	require.Len(t, allUseRows, 3)
}

func TestConsumeCredentialRejectClassifications(t *testing.T) {
	credentialStore := newCredentialStore(t)
	ctx := context.Background()
	now := time.Now()

	expiredCode := randomInstallCode()
	expiredRow, expiredCreateErr := credentialStore.CreateInstallCredentialWithAudit(ctx,
		hashInstallCode(expiredCode), "device", now.Add(-time.Minute), 3, "admin-a", "admin-a", nil)
	require.NoError(t, expiredCreateErr)
	_, expiredOutcome, expiredErr := credentialStore.ConsumeInstallCredential(ctx, hashInstallCode(expiredCode), "10.0.0.1")
	require.NoError(t, expiredErr)
	assert.Equal(t, CredentialOutcomeRejectedExpired, expiredOutcome)

	disabledCode := randomInstallCode()
	disabledRow, _ := credentialStore.CreateInstallCredentialWithAudit(ctx,
		hashInstallCode(disabledCode), "device", now.Add(time.Hour), 3, "admin-a", "admin-a", nil)
	require.NoError(t, credentialStore.RevokeInstallCredentialWithAudit(ctx, disabledRow.ID, "admin-a"))
	_, disabledOutcome, disabledErr := credentialStore.ConsumeInstallCredential(ctx, hashInstallCode(disabledCode), "10.0.0.1")
	require.NoError(t, disabledErr)
	assert.Equal(t, CredentialOutcomeRejectedDisabled, disabledOutcome)

	unknownCode := randomInstallCode()
	_, unknownOutcome, unknownErr := credentialStore.ConsumeInstallCredential(ctx, hashInstallCode(unknownCode), "10.0.0.1")
	require.NoError(t, unknownErr)
	assert.Equal(t, CredentialOutcomeRejectedInvalid, unknownOutcome)

	// 三类拒绝均落使用记录：过期/停用挂在各自凭据下，无效代码无凭据归属（ID 0 查空归属）。
	expiredUses, expiredTotal, _ := credentialStore.ListCredentialUses(ctx, expiredRow.ID, 1, 10)
	require.Equal(t, 1, expiredTotal)
	assert.Equal(t, CredentialOutcomeRejectedExpired, expiredUses[0].Outcome)

	disabledUses, disabledTotal, _ := credentialStore.ListCredentialUses(ctx, disabledRow.ID, 1, 10)
	require.Equal(t, 1, disabledTotal)
	assert.Equal(t, CredentialOutcomeRejectedDisabled, disabledUses[0].Outcome)

	unboundUses, unboundTotal, listErr := credentialStore.ListCredentialUses(ctx, 0, 1, 100)
	require.NoError(t, listErr)
	assert.Equal(t, 1, unboundTotal)
	assert.Nil(t, unboundUses[0].CredentialID, "无效代码使用记录不挂任何凭据")
	assert.Equal(t, CredentialOutcomeRejectedInvalid, unboundUses[0].Outcome)
}

func TestConsumeCredentialSetDeviceIDLink(t *testing.T) {
	credentialStore := newCredentialStore(t)
	ctx := context.Background()

	code, credentialID := mustSeedCredential(t, credentialStore, 1)
	useID, outcome, consumeErr := credentialStore.ConsumeInstallCredential(ctx, hashInstallCode(code), "10.0.0.9")
	require.NoError(t, consumeErr)
	assert.Equal(t, CredentialOutcomeSuccess, outcome)

	require.NoError(t, credentialStore.SetCredentialUseDeviceID(ctx, useID, "dev-linked-001"))

	useRows, total, listErr := credentialStore.ListCredentialUses(ctx, credentialID, 1, 10)
	require.NoError(t, listErr)
	require.Len(t, useRows, 1)
	assert.Equal(t, 1, total)
	assert.Equal(t, "dev-linked-001", useRows[0].DeviceID, "注册成功后应回填设备归属")
	assert.Equal(t, "10.0.0.9", useRows[0].ClientIP)
}

func TestConsumeCredentialConcurrentNoDoubleCount(t *testing.T) {
	credentialStore := newCredentialStore(t)
	ctx := context.Background()
	code, _ := mustSeedCredential(t, credentialStore, 1)
	codeHash := hashInstallCode(code)

	const competitors = 20
	successCount := 0
	var mu sync.Mutex
	var waitGroup sync.WaitGroup

	for i := 0; i < competitors; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, outcome, consumeErr := credentialStore.ConsumeInstallCredential(ctx, codeHash, "10.0.0.5")
			require.NoError(t, consumeErr)
			if outcome == CredentialOutcomeSuccess {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}
	waitGroup.Wait()

	assert.Equal(t, 1, successCount, "单次用量凭据并发消费只允许一次成功")
	credentialList, _ := credentialStore.ListInstallCredentials(ctx)
	require.Len(t, credentialList, 1)
	assert.Equal(t, 1, credentialList[0].UsesCount, "并发不双花计数")
}