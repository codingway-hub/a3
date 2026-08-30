-- 0008: 规则操作级审计留痕 + 设备吊销/恢复复用同一机制。
--
-- 背景：rules 表仅有 created_at/updated_at/deleted_at 时间戳，「谁在何时改了什么规则」
-- 不可追溯。新增 audit_log 记录控制台敏感操作（规则 CRUD/启停、设备吊销/恢复）的
-- 操作者、目标与变更前后状态快照；规则表同步补 updated_by 记录最近一次修改者。
-- before_state/after_state 为 JSONB 快照，由业务层序列化写入；审计与业务写同事务，
-- 保证「变更已生效则留痕必在」。

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL CHECK (action IN (
        'rule_create', 'rule_update', 'rule_patch', 'rule_delete',
        'device_revoke', 'device_restore')),
    target_type TEXT NOT NULL CHECK (target_type IN ('rule', 'device')),
    target_id TEXT NOT NULL,
    operator TEXT NOT NULL,
    before_state JSONB,
    after_state JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_target_idx ON audit_log (target_type, target_id, id DESC);
CREATE INDEX audit_log_created_idx ON audit_log (created_at DESC);

ALTER TABLE rules ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
