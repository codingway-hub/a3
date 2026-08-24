// Package servetest 为服务端各包的集成测试提供共享数据库夹具：
// 统一 DSN 解析、迁移应用与表清理。库不可达时用例自动跳过（本地开发约定）。
package servetest

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/store"
)

// DefaultTestDatabaseURL 是 make dev-db-up 拉起的本地集成库地址。
const DefaultTestDatabaseURL = "postgres://a3:a3@127.0.0.1:5433/a3_test?sslmode=disable"

// TestDatabaseURL 返回集成库 DSN（优先 TEST_DATABASE_URL 环境变量）。
func TestDatabaseURL(t *testing.T) string {
	t.Helper()
	if fromEnv := os.Getenv("TEST_DATABASE_URL"); fromEnv != "" {
		return fromEnv
	}
	return DefaultTestDatabaseURL
}

// NewTestPool 建立连接池并确保迁移已应用；连接失败时跳过当前用例。
func NewTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	poolConfig, parseErr := pgxpool.ParseConfig(TestDatabaseURL(t))
	require.NoError(t, parseErr)

	testPool, connectErr := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if connectErr != nil {
		t.Skipf("集成测试库不可达，跳过：%v", connectErr)
	}
	t.Cleanup(testPool.Close)

	connection, acquireErr := testPool.Acquire(context.Background())
	require.NoError(t, acquireErr)
	defer connection.Release()
	require.NoError(t, store.Migrate(context.Background(), connection.Conn()))

	return testPool
}

// ResetTablesForTest 清空指定业务表（连带外键级联行），保证用例间互不污染。
func ResetTablesForTest(t *testing.T, testPool *pgxpool.Pool, tableNames ...string) {
	t.Helper()
	for _, tableName := range tableNames {
		_, execErr := testPool.Exec(context.Background(), `TRUNCATE TABLE `+tableName+` CASCADE`)
		require.NoError(t, execErr)
	}
}

// MustSeedDevice 写入一台最小设备行，供事件/会话等外键场景使用。
func MustSeedDevice(t *testing.T, deviceStore *store.Store, deviceID string) {
	t.Helper()
	createErr := deviceStore.CreateDevice(context.Background(),
		&store.Device{DeviceID: deviceID, TokenHash: "hash-" + deviceID, Hostname: "host-" + deviceID})
	require.NoError(t, createErr)
}
