// Package migrations 内嵌 PostgreSQL 迁移 SQL 文件（golang-migrate 命名法：
// <版本号>_<名称>.up.sql / .down.sql），由 internal/server/store 的迁移器
// 在启动时按版本号顺序执行未应用版本。
package migrations

import "embed"

// FS 以只读文件系统形式内嵌全部迁移 SQL 文件。
//
//go:embed *.sql
var FS embed.FS
