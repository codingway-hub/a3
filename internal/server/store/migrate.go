// Package store 实现服务端 PostgreSQL 存储层。
// 本文件负责数据库 Schema 迁移：按嵌入迁移文件的版本号顺序，
// 在独立事务中执行未应用版本并登记，保证重复调用幂等。
package store

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/codingway-hub/a3/migrations"
)

// upMigrationFileNamePattern 匹配升级迁移文件名（golang-migrate 命名法：
// <纯数字版本号>_<名称>.up.sql），捕获组 1 为版本号。
var upMigrationFileNamePattern = regexp.MustCompile(`^([0-9]+)_.+\.up\.sql$`)

// schemaMigrationsTableName 记录已应用迁移版本的簿记表名（由本迁移器创建与管理）。
const schemaMigrationsTableName = "schema_migrations"

// migrationFile 一个待执行的迁移：版本号、来源文件名与 SQL 正文。
type migrationFile struct {
	version    int
	fileName   string
	sqlContent string
}

// Migrate 将数据库 Schema 推进至嵌入迁移的最新版本。
//
// 行为约定：
//   - 首次调用自动创建簿记表 schema_migrations(version INT PRIMARY KEY,
//     applied_at TIMESTAMPTZ DEFAULT now())；
//   - 每个迁移文件在其独立的数据库事务中执行（SQL 文件自身不含 BEGIN/COMMIT），
//     应用成功后写入版本记录；任一步失败则该迁移整体回滚并中止后续迁移；
//   - 已应用的版本跳过，重复调用幂等。
func Migrate(ctx context.Context, databaseConn *pgx.Conn) error {
	if _, err := databaseConn.Exec(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (
			version    INT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`, schemaMigrationsTableName)); err != nil {
		return fmt.Errorf("创建 %s 表失败: %w", schemaMigrationsTableName, err)
	}

	appliedVersions, err := loadAppliedVersions(ctx, databaseConn)
	if err != nil {
		return err
	}
	pendingMigrations, err := loadPendingMigrations(appliedVersions)
	if err != nil {
		return err
	}

	for _, pendingMigration := range pendingMigrations {
		if applyErr := applySingleMigration(ctx, databaseConn, pendingMigration); applyErr != nil {
			return applyErr
		}
	}
	return nil
}

// loadAppliedVersions 读取已应用的迁移版本号集合。
func loadAppliedVersions(ctx context.Context, databaseConn *pgx.Conn) ([]int, error) {
	versionRows, queryErr := databaseConn.Query(ctx,
		fmt.Sprintf(`SELECT version FROM %s ORDER BY version`, schemaMigrationsTableName))
	if queryErr != nil {
		return nil, fmt.Errorf("读取已应用迁移版本失败: %w", queryErr)
	}
	defer versionRows.Close()

	appliedVersions := []int{}
	for versionRows.Next() {
		var appliedVersion int
		if scanErr := versionRows.Scan(&appliedVersion); scanErr != nil {
			return nil, fmt.Errorf("扫描已应用迁移版本失败: %w", scanErr)
		}
		appliedVersions = append(appliedVersions, appliedVersion)
	}
	return appliedVersions, versionRows.Err()
}

// loadPendingMigrations 枚举内嵌的 *.up.sql 迁移文件，按版本号升序返回尚未应用的迁移。
func loadPendingMigrations(appliedVersions []int) ([]migrationFile, error) {
	dirEntries, readDirErr := fs.ReadDir(migrations.FS, ".")
	if readDirErr != nil {
		return nil, fmt.Errorf("枚举内嵌迁移文件失败: %w", readDirErr)
	}

	pendingMigrations := []migrationFile{}
	for _, dirEntry := range dirEntries {
		matchedSubmatches := upMigrationFileNamePattern.FindStringSubmatch(dirEntry.Name())
		if matchedSubmatches == nil {
			continue
		}
		migrationVersion, parseErr := strconv.Atoi(matchedSubmatches[1])
		if parseErr != nil {
			return nil, fmt.Errorf("解析迁移文件 %s 的版本号失败: %w", dirEntry.Name(), parseErr)
		}
		if slices.Contains(appliedVersions, migrationVersion) {
			continue
		}
		sqlContentBytes, readFileErr := migrations.FS.ReadFile(dirEntry.Name())
		if readFileErr != nil {
			return nil, fmt.Errorf("读取迁移文件 %s 失败: %w", dirEntry.Name(), readFileErr)
		}
		pendingMigrations = append(pendingMigrations, migrationFile{
			version:    migrationVersion,
			fileName:   dirEntry.Name(),
			sqlContent: string(sqlContentBytes),
		})
	}
	slices.SortFunc(pendingMigrations, func(left, right migrationFile) int {
		return left.version - right.version
	})
	return pendingMigrations, nil
}

// applySingleMigration 在独立事务中执行单个迁移文件并登记版本号。
//
// 迁移正文是多语句 SQL：pgx 扩展协议的单条预编译语句无法承载多语句，
// 故经同一连接底层事务内的简单查询协议（PgConn.Exec）执行整段内容。
func applySingleMigration(ctx context.Context, databaseConn *pgx.Conn, migration migrationFile) error {
	tx, beginErr := databaseConn.Begin(ctx)
	if beginErr != nil {
		return fmt.Errorf("为迁移 %s 开启事务失败: %w", migration.fileName, beginErr)
	}
	defer func() { _ = tx.Rollback(ctx) }() // 提交成功后再回滚为无操作

	if _, execErr := tx.Conn().PgConn().Exec(ctx, migration.sqlContent).ReadAll(); execErr != nil {
		return fmt.Errorf("执行迁移 %s 失败: %w", migration.fileName, execErr)
	}
	if _, recordErr := tx.Exec(ctx,
		fmt.Sprintf(`INSERT INTO %s (version) VALUES ($1)`, schemaMigrationsTableName),
		migration.version); recordErr != nil {
		return fmt.Errorf("登记迁移版本 %d 失败: %w", migration.version, recordErr)
	}
	if commitErr := tx.Commit(ctx); commitErr != nil {
		return fmt.Errorf("提交迁移 %s 事务失败: %w", migration.fileName, commitErr)
	}
	return nil
}
