package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// defaultTestDatabaseURL 为本地 docker 开发库（make dev-db-up 起的 a3-postgres-dev）。
const defaultTestDatabaseURL = "postgres://a3:a3@127.0.0.1:5433/a3_test?sslmode=disable"

// newTestPool 连接集成测试库并确保表结构存在；数据库不可达时跳过用例。
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = defaultTestDatabaseURL
	}
	ctx := context.Background()
	pool, err := NewPool(ctx, databaseURL)
	if err != nil {
		t.Skipf("integration database unavailable: %v", err)
	}
	if pingErr := pool.Ping(ctx); pingErr != nil {
		pool.Close()
		t.Skipf("integration database unreachable: %v", pingErr)
	}

	connection, acquireErr := pool.Acquire(ctx)
	require.NoError(t, acquireErr)
	defer connection.Release()
	require.NoError(t, Migrate(ctx, connection.Conn()), "apply embedded migrations")

	t.Cleanup(pool.Close)
	return pool
}

// testDatabaseURLForTest 返回集成库连接串（优先 TEST_DATABASE_URL 环境变量）。
func testDatabaseURLForTest(t *testing.T) string {
	t.Helper()
	if fromEnv := os.Getenv("TEST_DATABASE_URL"); fromEnv != "" {
		return fromEnv
	}
	return defaultTestDatabaseURL
}

// newFreshTestPool 建立不经迁移与跳过逻辑的裸连接池（整库重置类用例专用）。
func newFreshTestPool(t *testing.T) (*pgxpool.Pool, error) {
	t.Helper()
	return NewPool(context.Background(), testDatabaseURLForTest(t))
}

// resetTablesForTest 清空指定表数据，保证用例可重复运行。
func resetTablesForTest(t *testing.T, pool *pgxpool.Pool, tableNames ...string) {
	t.Helper()
	for _, tableName := range tableNames {
		_, execErr := pool.Exec(context.Background(), "TRUNCATE TABLE "+tableName+" CASCADE")
		require.NoError(t, execErr)
	}
}
