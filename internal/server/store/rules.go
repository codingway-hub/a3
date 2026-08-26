package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// RuleRecord 对应 rules 表一行；Matcher 为规则匹配器的 jsonb 原文。
// 软删（deleted_at 非空）的行在本层全部查询中过滤，对上层不可见。
type RuleRecord struct {
	ID        string
	Name      string
	Category  string
	Matcher   []byte
	Severity  string
	Action    string
	Enabled   bool
	Builtin   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

const ruleColumns = `id, name, category, matcher, severity, action, enabled, builtin, created_at, updated_at`

// scanRuleRecord 把当前行扫描进 RuleRecord（列序与 ruleColumns 一致）。
func scanRuleRecord(row pgx.Row) (RuleRecord, error) {
	var rule RuleRecord
	scanErr := row.Scan(&rule.ID, &rule.Name, &rule.Category, &rule.Matcher, &rule.Severity,
		&rule.Action, &rule.Enabled, &rule.Builtin, &rule.CreatedAt, &rule.UpdatedAt)
	return rule, scanErr
}

// GetRule 按 id 查单条规则；不存在或已软删返回 ErrNotFound。
func (store *Store) GetRule(ctx context.Context, ruleID string) (RuleRecord, error) {
	rule, scanErr := scanRuleRecord(store.pool.QueryRow(ctx,
		`SELECT `+ruleColumns+` FROM rules WHERE id = $1 AND deleted_at IS NULL`, ruleID))
	if errors.Is(scanErr, pgx.ErrNoRows) {
		return RuleRecord{}, ErrNotFound
	}
	return rule, scanErr
}

// ListRules 返回全部规则（含停用，不含软删），按 id 排序保证展示稳定。
func (store *Store) ListRules(ctx context.Context) ([]RuleRecord, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT `+ruleColumns+` FROM rules WHERE deleted_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]RuleRecord, 0)
	for rows.Next() {
		rule, scanErr := scanRuleRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ListEnabledRules 返回全部启用中的规则（规则引擎热加载与终端下发组装用）。
func (store *Store) ListEnabledRules(ctx context.Context) ([]RuleRecord, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT `+ruleColumns+` FROM rules WHERE enabled = true AND deleted_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]RuleRecord, 0)
	for rows.Next() {
		rule, scanErr := scanRuleRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// SetRuleEnabled 启停规则并刷新 updated_at；软删行不可启停。
func (store *Store) SetRuleEnabled(ctx context.Context, ruleID string, enabled bool) error {
	commandTag, err := store.pool.Exec(ctx,
		`UPDATE rules SET enabled = $2, updated_at = now()
		 WHERE id = $1 AND deleted_at IS NULL`, ruleID, enabled)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateRule 新建自定义规则；id 唯一键冲突返回 ErrAlreadyExists。
func (store *Store) CreateRule(ctx context.Context, ruleRecord *RuleRecord) error {
	createErr := store.pool.QueryRow(ctx,
		`INSERT INTO rules (id, name, category, matcher, severity, action, enabled, builtin)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING created_at, updated_at`,
		ruleRecord.ID, ruleRecord.Name, ruleRecord.Category, ruleRecord.Matcher,
		ruleRecord.Severity, ruleRecord.Action, ruleRecord.Enabled, ruleRecord.Builtin,
	).Scan(&ruleRecord.CreatedAt, &ruleRecord.UpdatedAt)
	return mapUniqueViolation(createErr)
}

// UpdateRule 全量更新自定义规则内容；builtin 与已软删行不可更新（返回 ErrNotFound）。
func (store *Store) UpdateRule(ctx context.Context, ruleRecord *RuleRecord) error {
	commandTag, err := store.pool.Exec(ctx,
		`UPDATE rules SET name = $2, category = $3, matcher = $4, severity = $5,
		        action = $6, enabled = $7, updated_at = now()
		 WHERE id = $1 AND builtin = false AND deleted_at IS NULL`,
		ruleRecord.ID, ruleRecord.Name, ruleRecord.Category, ruleRecord.Matcher,
		ruleRecord.Severity, ruleRecord.Action, ruleRecord.Enabled)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteRule 软删自定义规则：置位 deleted_at 并同时停用；
// builtin 与已软删行不可删除（返回 ErrNotFound）。
func (store *Store) DeleteRule(ctx context.Context, ruleID string) error {
	commandTag, err := store.pool.Exec(ctx,
		`UPDATE rules SET deleted_at = now(), enabled = false, updated_at = now()
		 WHERE id = $1 AND builtin = false AND deleted_at IS NULL`, ruleID)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
