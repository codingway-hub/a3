-- 0010: RBAC 分角色权限——admin_users 表 + 审计约束扩展。
--
-- 控制台从单管理员（env 凭据）升级为数据库多账号：admin 全权；auditor 只读 + 确认告警。
-- 现有 env 凭据仅在首次启动（表空时）由服务端种子成 admin 账号，之后改密走控制台。
-- 用户账号的创建/停用/改角色/重置密码均入 audit_log 留痕（与规则/设备变更同机制）。

CREATE TABLE admin_users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'auditor')),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- audit_log 的 action/target_type CHECK 为 0008 内联定义，扩展合法值需删重建
ALTER TABLE audit_log DROP CONSTRAINT audit_log_action_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check CHECK (action IN (
    'rule_create', 'rule_update', 'rule_patch', 'rule_delete',
    'device_revoke', 'device_restore',
    'user_create', 'user_update', 'user_password_reset'));

ALTER TABLE audit_log DROP CONSTRAINT audit_log_target_type_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_target_type_check CHECK (target_type IN ('rule', 'device', 'user'));
