package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
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
	UpdatedBy string
}

const ruleColumns = `id, name, category, matcher, severity, action, enabled, builtin, created_at, updated_at, updated_by`

// scanRuleRecord 把当前行扫描进 RuleRecord（列序与 ruleColumns 一致）。
func scanRuleRecord(row pgx.Row) (RuleRecord, error) {
	var rule RuleRecord
	scanErr := row.Scan(&rule.ID, &rule.Name, &rule.Category, &rule.Matcher, &rule.Severity,
		&rule.Action, &rule.Enabled, &rule.Builtin, &rule.CreatedAt, &rule.UpdatedAt, &rule.UpdatedBy)
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

// SetRuleEnabled 启停规则并刷新 updated_at/updated_by，同事务落一条 rule_patch 审计
// （before/after 均含 enabled 状态）；软删行不可启停。审计与业务写同事务：变更生效则留痕必在。
func (store *Store) SetRuleEnabled(ctx context.Context, ruleID string, enabled bool, operator string) error {
	return store.withTx(ctx, func(tx pgx.Tx) error {
		var beforeEnabled bool
		scanErr := tx.QueryRow(ctx,
			`SELECT enabled FROM rules WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, ruleID).
			Scan(&beforeEnabled)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if scanErr != nil {
			return scanErr
		}
		commandTag, execErr := tx.Exec(ctx,
			`UPDATE rules SET enabled = $2, updated_by = $3, updated_at = now()
			 WHERE id = $1 AND deleted_at IS NULL`, ruleID, enabled, operator)
		if execErr != nil {
			return execErr
		}
		if commandTag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return appendAuditInTx(ctx, tx, AuditActionRulePatch, auditTargetRule, ruleID, operator,
			[]byte(`{"enabled":`+strconv.FormatBool(beforeEnabled)+`}`),
			[]byte(`{"enabled":`+strconv.FormatBool(enabled)+`}`))
	})
}

// CreateRule 新建自定义规则并写 updated_by，同事务落一条 rule_create 审计；
// id 唯一键冲突返回 ErrAlreadyExists（事务回滚，无留痕）。
func (store *Store) CreateRule(ctx context.Context, ruleRecord *RuleRecord, operator string) error {
	return store.withTx(ctx, func(tx pgx.Tx) error {
		createErr := tx.QueryRow(ctx,
			`INSERT INTO rules (id, name, category, matcher, severity, action, enabled, builtin, updated_by)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 RETURNING created_at, updated_at`,
			ruleRecord.ID, ruleRecord.Name, ruleRecord.Category, ruleRecord.Matcher,
			ruleRecord.Severity, ruleRecord.Action, ruleRecord.Enabled, ruleRecord.Builtin, operator,
		).Scan(&ruleRecord.CreatedAt, &ruleRecord.UpdatedAt)
		if createErr != nil {
			return mapUniqueViolation(createErr)
		}
		return appendAuditInTx(ctx, tx, AuditActionRuleCreate, auditTargetRule, ruleRecord.ID, operator,
			nil, marshalRuleSnapshot(ruleRecord))
	})
}

// UpdateRule 全量更新自定义规则内容并写 updated_by，同事务落一条 rule_update 审计
// （before 为变更前完整快照）；builtin 与已软删行不可更新（返回 ErrNotFound，无留痕）。
func (store *Store) UpdateRule(ctx context.Context, ruleRecord *RuleRecord, operator string) error {
	return store.withTx(ctx, func(tx pgx.Tx) error {
		beforeRow, beforeErr := selectRuleForUpdate(ctx, tx, ruleRecord.ID)
		if beforeErr != nil {
			return beforeErr
		}
		updateErr := updateRuleInTx(ctx, tx, ruleRecord, operator)
		if updateErr != nil {
			return updateErr
		}
		return appendAuditInTx(ctx, tx, AuditActionRuleUpdate, auditTargetRule, ruleRecord.ID, operator,
			marshalRuleSnapshot(&beforeRow), marshalRuleSnapshot(ruleRecord))
	})
}

// DeleteRule 软删自定义规则（置位 deleted_at 并停用），同事务落一条 rule_delete 审计
// （before 为删除前完整快照）；builtin 与已软删行不可删除（返回 ErrNotFound，无留痕）。
func (store *Store) DeleteRule(ctx context.Context, ruleID string, operator string) error {
	return store.withTx(ctx, func(tx pgx.Tx) error {
		beforeRow, beforeErr := selectRuleForUpdate(ctx, tx, ruleID)
		if beforeErr != nil {
			return beforeErr
		}
		commandTag, execErr := tx.Exec(ctx,
			`UPDATE rules SET deleted_at = now(), enabled = false, updated_by = $2, updated_at = now()
			 WHERE id = $1 AND builtin = false AND deleted_at IS NULL`, ruleID, operator)
		if execErr != nil {
			return execErr
		}
		if commandTag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return appendAuditInTx(ctx, tx, AuditActionRuleDelete, auditTargetRule, ruleID, operator,
			marshalRuleSnapshot(&beforeRow), nil)
	})
}

// selectRuleForUpdate 取当前规则行并加行锁（FOR UPDATE），作为变更前快照来源；
// 不存在或已软删返回 ErrNotFound。
func selectRuleForUpdate(ctx context.Context, tx pgx.Tx, ruleID string) (RuleRecord, error) {
	rule, scanErr := scanRuleRecord(tx.QueryRow(ctx,
		`SELECT `+ruleColumns+` FROM rules WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, ruleID))
	if errors.Is(scanErr, pgx.ErrNoRows) {
		return RuleRecord{}, ErrNotFound
	}
	return rule, scanErr
}

// updateRuleInTx 在事务内执行规则内容全量更新（builtin 守护与 SetRuleEnabled 同款 WHERE 守护）。
func updateRuleInTx(ctx context.Context, tx pgx.Tx, ruleRecord *RuleRecord, operator string) error {
	commandTag, err := tx.Exec(ctx,
		`UPDATE rules SET name = $2, category = $3, matcher = $4, severity = $5,
		        action = $6, enabled = $7, updated_by = $8, updated_at = now()
		 WHERE id = $1 AND builtin = false AND deleted_at IS NULL`,
		ruleRecord.ID, ruleRecord.Name, ruleRecord.Category, ruleRecord.Matcher,
		ruleRecord.Severity, ruleRecord.Action, ruleRecord.Enabled, operator)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// marshalRuleSnapshot 规则审计快照：仅记录运营可见字段，matcher 保持 JSON 原文。
func marshalRuleSnapshot(ruleRecord *RuleRecord) []byte {
	snapshot, marshalErr := json.Marshal(map[string]any{
		"id": ruleRecord.ID, "name": ruleRecord.Name, "category": ruleRecord.Category,
		"matcher": json.RawMessage(ruleRecord.Matcher), "severity": ruleRecord.Severity,
		"action": ruleRecord.Action, "enabled": ruleRecord.Enabled,
	})
	if marshalErr != nil {
		// Matcher 已是合法 JSON，序列化只可能因 RawMessage 空值失败；快照缺失不阻断业务写
		return nil
	}
	return snapshot
}
