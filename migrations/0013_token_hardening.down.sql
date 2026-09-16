-- 回滚 0013：移除 token_version / token_expires_at 列，恢复 0011 的审计合法取值集合。

ALTER TABLE devices
    DROP COLUMN token_expires_at;

ALTER TABLE admin_users
    DROP COLUMN token_version;

ALTER TABLE audit_log DROP CONSTRAINT audit_log_action_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check CHECK (action IN (
    'rule_create', 'rule_update', 'rule_patch', 'rule_delete',
    'device_revoke', 'device_restore', 'device_token_rotate',
    'credential_create', 'credential_revoke',
    'user_create', 'user_update', 'user_password_reset'));