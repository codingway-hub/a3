package store_test

import (
	"context"
	"io/fs"
	"os"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/migrations"
)

// countEmbeddedUpMigrations 统计内嵌的 up 迁移文件数（期望应用版本数随之联动）。
func countEmbeddedUpMigrations(t *testing.T) int {
	t.Helper()
	upFileMatches, globErr := fs.Glob(migrations.FS, "*.up.sql")
	if globErr != nil {
		t.Fatalf("枚举内嵌迁移文件失败: %v", globErr)
	}
	return len(upFileMatches)
}

// defaultTestDatabaseURL 本地开发库默认连接串，与 deploy/dev/docker-compose.dev.yml 对齐。
const defaultTestDatabaseURL = "postgres://a3:a3@127.0.0.1:5433/a3_test?sslmode=disable"

// expectedTableNames 迁移完成后 public schema 应存在的全部表（五张业务表 + 迁移记录表）。
var expectedTableNames = []string{
	"alerts",
	"devices",
	"events",
	"rules",
	"schema_migrations",
	"sessions",
}

// builtinRuleIDs 全部 14 条内置规则的 ID，种子完整性按集合精确比对。
var builtinRuleIDs = []string{
	"dlp.aws_access_key",
	"dlp.aws_secret_key",
	"dlp.private_key_block",
	"dlp.generic_api_key",
	"dlp.jwt",
	"dlp.db_conn_string",
	"cmd.rm_rf_root",
	"cmd.git_force_push",
	"cmd.remote_script_exec",
	"cmd.chmod_privilege",
	"cmd.disk_wipe",
	"file.ssh_private_read",
	"file.dotenv_access",
	"git.history_rewrite",
}

func TestMigrateCreatesAllTables(t *testing.T) {
	testConn := newIntegrationTestConnection(t)
	resetDatabaseSchema(t, testConn)
	testContext := context.Background()

	if migrateErr := store.Migrate(testContext, testConn); migrateErr != nil {
		t.Fatalf("首次 Migrate 不应报错: %v", migrateErr)
	}

	tableRows, queryErr := testConn.Query(testContext,
		`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`)
	if queryErr != nil {
		t.Fatalf("查询 information_schema.tables 失败: %v", queryErr)
	}
	defer tableRows.Close()

	actualTableNames := []string{}
	for tableRows.Next() {
		var tableName string
		if scanErr := tableRows.Scan(&tableName); scanErr != nil {
			t.Fatalf("扫描表名失败: %v", scanErr)
		}
		actualTableNames = append(actualTableNames, tableName)
	}
	if loopErr := tableRows.Err(); loopErr != nil {
		t.Fatalf("遍历表名失败: %v", loopErr)
	}

	slices.Sort(actualTableNames)
	if !slices.Equal(actualTableNames, expectedTableNames) {
		t.Fatalf("迁移后的表集合不符\n期望: %v\n实际: %v", expectedTableNames, actualTableNames)
	}
}

func TestMigrateIdempotentOnRepeatedCall(t *testing.T) {
	testConn := newIntegrationTestConnection(t)
	resetDatabaseSchema(t, testConn)
	testContext := context.Background()

	if firstMigrateErr := store.Migrate(testContext, testConn); firstMigrateErr != nil {
		t.Fatalf("第一次 Migrate 不应报错: %v", firstMigrateErr)
	}
	appliedVersionCount := countAppliedVersions(t, testConn)
	expectedVersionCount := countEmbeddedUpMigrations(t)
	if appliedVersionCount != expectedVersionCount {
		t.Fatalf("首次迁移后 schema_migrations 应恰好记录 %d 个版本（与内嵌 up 文件数一致）, 实际 %d",
			expectedVersionCount, appliedVersionCount)
	}

	if secondMigrateErr := store.Migrate(testContext, testConn); secondMigrateErr != nil {
		t.Fatalf("重复 Migrate 不应报错: %v", secondMigrateErr)
	}
	if recountAfterSecondCall := countAppliedVersions(t, testConn); recountAfterSecondCall != appliedVersionCount {
		t.Fatalf("重复 Migrate 后版本数应保持 %d 不变, 实际 %d", appliedVersionCount, recountAfterSecondCall)
	}
}

func TestMigrateSeedsExactlyFourteenEnabledRules(t *testing.T) {
	testConn := newIntegrationTestConnection(t)
	resetDatabaseSchema(t, testConn)
	testContext := context.Background()

	if migrateErr := store.Migrate(testContext, testConn); migrateErr != nil {
		t.Fatalf("Migrate 不应报错: %v", migrateErr)
	}

	var totalRuleCount int
	var enabledRuleCount int
	countScanErr := testConn.QueryRow(testContext,
		`SELECT count(*), count(*) FILTER (WHERE enabled) FROM rules`).
		Scan(&totalRuleCount, &enabledRuleCount)
	if countScanErr != nil {
		t.Fatalf("统计 rules 表失败: %v", countScanErr)
	}
	if totalRuleCount != len(builtinRuleIDs) || enabledRuleCount != len(builtinRuleIDs) {
		t.Fatalf("内置规则应为 %d 条且全部 enabled=true, 实际 total=%d enabled=%d",
			len(builtinRuleIDs), totalRuleCount, enabledRuleCount)
	}

	ruleIDRows, queryErr := testConn.Query(testContext, `SELECT id FROM rules ORDER BY id`)
	if queryErr != nil {
		t.Fatalf("查询规则 ID 失败: %v", queryErr)
	}
	defer ruleIDRows.Close()

	actualRuleIDs := []string{}
	for ruleIDRows.Next() {
		var ruleID string
		if scanErr := ruleIDRows.Scan(&ruleID); scanErr != nil {
			t.Fatalf("扫描规则 ID 失败: %v", scanErr)
		}
		actualRuleIDs = append(actualRuleIDs, ruleID)
	}
	if loopErr := ruleIDRows.Err(); loopErr != nil {
		t.Fatalf("遍历规则 ID 失败: %v", loopErr)
	}
	slices.Sort(actualRuleIDs)
	expectedSortedRuleIDs := slices.Sorted(slices.Values(builtinRuleIDs))
	if !slices.Equal(actualRuleIDs, expectedSortedRuleIDs) {
		t.Fatalf("规则 ID 集合不符\n期望: %v\n实际: %v", expectedSortedRuleIDs, actualRuleIDs)
	}

	// matcher 形状统一校验：必须含 target 键，且 patterns / path_globs 至少其一。
	var malformedMatcherCount int
	malformedScanErr := testConn.QueryRow(testContext,
		`SELECT count(*) FROM rules
		 WHERE NOT (matcher ? 'target')
		    OR NOT (matcher ? 'patterns' OR matcher ? 'path_globs')`).
		Scan(&malformedMatcherCount)
	if malformedScanErr != nil {
		t.Fatalf("校验 matcher 形状失败: %v", malformedScanErr)
	}
	if malformedMatcherCount != 0 {
		t.Fatalf("存在 %d 条 matcher 形状不统一的规则", malformedMatcherCount)
	}
}

func TestDownMigrationThenMigrateRestoresUsableSchema(t *testing.T) {
	testConn := newIntegrationTestConnection(t)
	resetDatabaseSchema(t, testConn)
	testContext := context.Background()

	if initialMigrateErr := store.Migrate(testContext, testConn); initialMigrateErr != nil {
		t.Fatalf("首次 Migrate 不应报错: %v", initialMigrateErr)
	}

	downSQLContent, readDownErr := migrations.FS.ReadFile("0001_init.down.sql")
	if readDownErr != nil {
		t.Fatalf("读取 down.sql 失败: %v", readDownErr)
	}
	// down.sql 同为多语句 SQL，与迁移器一致走简单查询协议执行。
	if _, execDownErr := testConn.PgConn().Exec(testContext, string(downSQLContent)).ReadAll(); execDownErr != nil {
		t.Fatalf("执行 down.sql 不应报错: %v", execDownErr)
	}
	remainingBusinessTableCount := countBusinessTables(t, testConn)
	if remainingBusinessTableCount != 0 {
		t.Fatalf("down 之后五张业务表应全部清除, 实际残留 %d 张", remainingBusinessTableCount)
	}
	// down.sql 不负责清理迁移器的版本记录（bookkeeping 表由迁移器管理），
	// 此处手动清空以模拟「down 到零」后重新 up 的场景。
	if _, deleteErr := testConn.Exec(testContext, `DELETE FROM schema_migrations`); deleteErr != nil {
		t.Fatalf("清空 schema_migrations 失败: %v", deleteErr)
	}

	if reMigrateErr := store.Migrate(testContext, testConn); reMigrateErr != nil {
		t.Fatalf("down 后重新 Migrate 不应报错: %v", reMigrateErr)
	}
	rebuiltTableCount := countBusinessTables(t, testConn)
	if rebuiltTableCount != len(expectedTableNames)-1 { // 减去非业务表 schema_migrations
		t.Fatalf("重新迁移后应有 %d 张业务表, 实际 %d 张",
			len(expectedTableNames)-1, rebuiltTableCount)
	}
}

// newIntegrationTestConnection 连接集成测试库；数据库不可达时跳过用例而非失败。
func newIntegrationTestConnection(t *testing.T) *pgx.Conn {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = defaultTestDatabaseURL
	}
	testConn, connectErr := pgx.Connect(context.Background(), databaseURL)
	if connectErr != nil {
		t.Skipf("integration database unavailable: %v", connectErr)
	}
	t.Cleanup(func() { _ = testConn.Close(context.Background()) })
	return testConn
}

// resetDatabaseSchema 清空与迁移相关的全部对象，保证用例可独立、可重复运行。
func resetDatabaseSchema(t *testing.T, testConn *pgx.Conn) {
	t.Helper()
	_, dropErr := testConn.Exec(context.Background(),
		`DROP TABLE IF EXISTS rules, alerts, events, sessions, devices, schema_migrations CASCADE`)
	if dropErr != nil {
		t.Fatalf("重置数据库 Schema 失败: %v", dropErr)
	}
}

func countAppliedVersions(t *testing.T, testConn *pgx.Conn) int {
	t.Helper()
	var versionCount int
	scanErr := testConn.QueryRow(context.Background(),
		`SELECT count(*) FROM schema_migrations`).Scan(&versionCount)
	if scanErr != nil {
		t.Fatalf("查询 schema_migrations 版本数失败: %v", scanErr)
	}
	return versionCount
}

// countBusinessTables 统计五张业务表的现存数量（不含迁移记录表）。
func countBusinessTables(t *testing.T, testConn *pgx.Conn) int {
	t.Helper()
	businessTableNames := slices.DeleteFunc(slices.Clone(expectedTableNames),
		func(tableName string) bool { return tableName == "schema_migrations" })
	rows, queryErr := testConn.Query(context.Background(),
		`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = 'public' AND table_name = ANY($1::text[])`, businessTableNames)
	if queryErr != nil {
		t.Fatalf("统计业务表数量失败: %v", queryErr)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("count 查询未返回行")
	}
	var businessTableCount int
	if scanErr := rows.Scan(&businessTableCount); scanErr != nil {
		t.Fatalf("扫描业务表数量失败: %v", scanErr)
	}
	return businessTableCount
}
