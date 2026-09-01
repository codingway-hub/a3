-- 回滚 0011：删除安装凭据两张表，audit_log 约束恢复为 0010 的合法取值集合。

DROP TABLE IF EXISTS install_credential_uses;
DROP TABLE IF EXISTS install_credentials;

ALTER TABLE audit_log DROP CONSTRAINT audit_log_action_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check CHECK (action IN (
    'rule_create', 'rule_update', 'rule_patch', 'rule_delete',
    'device_revoke', 'device_restore',
    'user_create', 'user_update', 'user_password_reset'));

ALTER TABLE audit_log DROP CONSTRAINT audit_log_target_type_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_target_type_check CHECK (target_type IN ('rule', 'device', 'user'));