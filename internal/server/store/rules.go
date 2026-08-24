package store

import (
	"context"
	"time"
)

// RuleRecord 对应 rules 表一行；Matcher 为规则匹配器的 jsonb 原文。
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

// ListRules 返回全部规则（含停用），按 id 排序保证展示稳定。
func (store *Store) ListRules(ctx context.Context) ([]RuleRecord, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT `+ruleColumns+` FROM rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]RuleRecord, 0)
	for rows.Next() {
		var rule RuleRecord
		if scanErr := rows.Scan(&rule.ID, &rule.Name, &rule.Category, &rule.Matcher, &rule.Severity,
			&rule.Action, &rule.Enabled, &rule.Builtin, &rule.CreatedAt, &rule.UpdatedAt); scanErr != nil {
			return nil, scanErr
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ListEnabledRules 返回全部启用中的规则（规则引擎热加载用）。
func (store *Store) ListEnabledRules(ctx context.Context) ([]RuleRecord, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT `+ruleColumns+` FROM rules WHERE enabled = true ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]RuleRecord, 0)
	for rows.Next() {
		var rule RuleRecord
		if scanErr := rows.Scan(&rule.ID, &rule.Name, &rule.Category, &rule.Matcher, &rule.Severity,
			&rule.Action, &rule.Enabled, &rule.Builtin, &rule.CreatedAt, &rule.UpdatedAt); scanErr != nil {
			return nil, scanErr
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// SetRuleEnabled 启停规则并刷新 updated_at。
func (store *Store) SetRuleEnabled(ctx context.Context, ruleID string, enabled bool) error {
	commandTag, err := store.pool.Exec(ctx,
		`UPDATE rules SET enabled = $2, updated_at = now() WHERE id = $1`, ruleID, enabled)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
