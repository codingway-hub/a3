-- 0005: 自定义规则软删除。
--
-- 审计平台禁止 ID 复用歧义：硬删后重建同 ID 规则会让历史告警的命中解释
-- 指向一条同名不同义的规则（alerts.rule_id 行自包含、无外键，但控制台
-- 按 ID 关联规则名做展示）。deleted_at 非空即视为已删除：
--   - ListRules / ListEnabledRules / GetRule 过滤已删行；
--   - DeleteRule 置位 deleted_at 并同时停用（停用语义与软删一致）；
--   - builtin 规则不允许删除，仅允许启停（内容随种子迁移刷新）。

ALTER TABLE rules ADD COLUMN deleted_at TIMESTAMPTZ;
