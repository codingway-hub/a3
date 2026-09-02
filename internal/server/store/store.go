// Package store 提供 a3 服务端的 PostgreSQL 数据访问层。
//
// 设计约束：
//   - 手写 SQL，不引入 ORM；所有语句针对 migrations/0001_init 定义的表结构。
//   - 不 import pkg/schema：payload/risk_tags 等复杂字段以 []byte(jsonb 原文) 存取，
//     序列化职责归上层服务模块。
package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound 表示按键查询未命中任何记录。
var ErrNotFound = errors.New("record not found")

// ErrAlreadyExists 表示唯一键冲突（如同名规则 ID 已存在）。
var ErrAlreadyExists = errors.New("record already exists")

// mapUniqueViolation 把 PostgreSQL 唯一键冲突（23505）归一为 ErrAlreadyExists，
// 其余错误原样透传；调用层据此返回 409 而非 500。
func mapUniqueViolation(storeErr error) error {
	var pgError *pgconn.PgError
	if errors.As(storeErr, &pgError) && pgError.Code == "23505" {
		return ErrAlreadyExists
	}
	return storeErr
}

// likeEscaper 把 ILIKE 关键字中的通配符与转义符替换为字面量形式。
var likeEscaper = strings.NewReplacer(
	`\`, `\\`,
	`%`, `\%`,
	`_`, `\_`,
)

// Store 聚合五域数据访问方法，持有共享连接池。
type Store struct {
	pool *pgxpool.Pool
}

// NewStore 基于既有连接池构造 Store。
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Ping 探测连接池可用性（存活/就绪探针用）。
func (store *Store) Ping(ctx context.Context) error {
	return store.pool.Ping(ctx)
}

// NewPool 建立 PostgreSQL 连接池。
func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, poolConfig)
}

// normalizePage 把分页参数收敛到合法区间：page 从 1 起，pageSize 默认 20、上限 100。
func normalizePage(page, pageSize int) (normalizedPage int, normalizedPageSize int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

// pageWindow 计算分页的 LIMIT 与 OFFSET。
func pageWindow(page, pageSize int) (limit int, offset int) {
	return pageSize, (page - 1) * pageSize
}

// likePatternContains 把任意关键字转义为 ILIKE 的"包含"匹配模式。
func likePatternContains(keyword string) string {
	return "%" + likeEscaper.Replace(keyword) + "%"
}
