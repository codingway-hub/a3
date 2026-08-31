package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustCreateUser 直接落一个账号（哈希值无意义，登录校验在 api 层测）。
func mustCreateUser(t *testing.T, userStore *Store, username string, role string) {
	t.Helper()
	require.NoError(t, userStore.CreateAdminUser(context.Background(), username, "hash-"+username, role))
}

func TestAdminUserLifecycle(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "admin_users")
	userStore := NewStore(testPool)
	ctx := context.Background()

	// 初始为空（种子判断依据）
	userCount, countErr := userStore.CountAdminUsers(ctx)
	require.NoError(t, countErr)
	assert.Equal(t, 0, userCount)

	require.NoError(t, userStore.CreateAdminUser(ctx, "admin", "hash-admin", "admin"))
	require.NoError(t, userStore.CreateAdminUser(ctx, "auditor1", "hash-auditor1", "auditor"))
	// 同名冲突归一为 ErrAlreadyExists
	duplicateErr := userStore.CreateAdminUser(ctx, "admin", "hash-other", "admin")
	assert.ErrorIs(t, duplicateErr, ErrAlreadyExists)

	userCount, countErr = userStore.CountAdminUsers(ctx)
	require.NoError(t, countErr)
	assert.Equal(t, 2, userCount)

	// 认证查询返回完整行（含哈希）
	fetched, fetchErr := userStore.GetAdminUserByUsername(ctx, "admin")
	require.NoError(t, fetchErr)
	assert.Equal(t, "hash-admin", fetched.PasswordHash)
	assert.Equal(t, "admin", fetched.Role)
	assert.True(t, fetched.Enabled)

	// 不存在 → ErrNotFound
	_, missingErr := userStore.GetAdminUserByUsername(ctx, "nobody")
	assert.ErrorIs(t, missingErr, ErrNotFound)

	// 列表不含哈希
	userList, listErr := userStore.ListAdminUsers(ctx)
	require.NoError(t, listErr)
	require.Len(t, userList, 2)
	assert.Equal(t, "admin", userList[0].Username)
	assert.Empty(t, userList[0].PasswordHash, "列表不得回口令哈希")
	assert.Equal(t, "auditor1", userList[1].Username)
}

func TestAdminUserUpdates(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "admin_users")
	userStore := NewStore(testPool)
	ctx := context.Background()

	mustCreateUser(t, userStore, "admin", "admin")
	mustCreateUser(t, userStore, "auditor1", "auditor")
	auditorRow, fetchErr := userStore.GetAdminUserByUsername(ctx, "auditor1")
	require.NoError(t, fetchErr)

	// 停用后读取 enabled=false；返回行供审计快照
	updatedRow, disableErr := userStore.SetAdminUserEnabled(ctx, auditorRow.ID, false)
	require.NoError(t, disableErr)
	assert.False(t, updatedRow.Enabled)
	assert.Equal(t, "auditor1", updatedRow.Username)

	refetched, refetchErr := userStore.GetAdminUserByUsername(ctx, "auditor1")
	require.NoError(t, refetchErr)
	assert.False(t, refetched.Enabled)

	// 改角色
	roleRow, roleErr := userStore.SetAdminUserRole(ctx, auditorRow.ID, "admin")
	require.NoError(t, roleErr)
	assert.Equal(t, "admin", roleRow.Role)

	// 重置口令
	require.NoError(t, userStore.SetAdminUserPassword(ctx, auditorRow.ID, "hash-new"))
	passwordRow, passwordErr := userStore.GetAdminUserByUsername(ctx, "auditor1")
	require.NoError(t, passwordErr)
	assert.Equal(t, "hash-new", passwordRow.PasswordHash)

	// 不存在的 ID → ErrNotFound
	_, missingErr := userStore.SetAdminUserEnabled(ctx, 99999, false)
	assert.ErrorIs(t, missingErr, ErrNotFound)
	_, missingRoleErr := userStore.SetAdminUserRole(ctx, 99999, "admin")
	assert.ErrorIs(t, missingRoleErr, ErrNotFound)
	assert.ErrorIs(t, userStore.SetAdminUserPassword(ctx, 99999, "hash-x"), ErrNotFound)
}

func TestAdminUserRoleConstraint(t *testing.T) {
	testPool := newTestPool(t)
	resetTablesForTest(t, testPool, "admin_users")
	userStore := NewStore(testPool)
	ctx := context.Background()

	// 迁移 CHECK 兜底：非法角色落库被数据库拒绝
	constraintErr := userStore.CreateAdminUser(ctx, "badrole", "hash-x", "superuser")
	require.Error(t, constraintErr)
	assert.NotErrorIs(t, constraintErr, ErrAlreadyExists)
}
