-- 安装凭据（注册门禁）：管理员下发的一次性接入代码，注册端点原子消费。
-- 明文代码仅在生成接口返回一次，表中仅存 SHA-256 摘要；使用结果写入
-- install_credential_uses 供追溯（成功 / 过期 / 停用 / 用量用尽 / 无效 / 限流）。

CREATE TABLE install_credentials (
    id          BIGSERIAL PRIMARY KEY,
    code_hash   TEXT NOT NULL UNIQUE,
    scope       TEXT NOT NULL DEFAULT 'device' CHECK (scope IN ('device')),
    expires_at  TIMESTAMPTZ NOT NULL,
    max_uses    INT NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 10000),
    uses_count  INT NOT NULL DEFAULT 0 CHECK (uses_count >= 0),
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 凭据使用记录：rate_limited 与无效代码无关联凭据，credential_id 允许为空。
CREATE TABLE install_credential_uses (
    id            BIGSERIAL PRIMARY KEY,
    credential_id BIGINT REFERENCES install_credentials(id) ON DELETE SET NULL,
    outcome       TEXT NOT NULL CHECK (outcome IN (
        'success', 'rejected_expired', 'rejected_disabled',
        'rejected_used', 'rejected_invalid', 'rate_limited')),
    device_id     TEXT NOT NULL DEFAULT '',
    client_ip     TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_install_credential_uses_cred ON install_credential_uses (credential_id, created_at);

-- 审计动作扩展：设备 Token 轮换（仅管理员批准路径）与安装凭据创建/吊销。
ALTER TABLE audit_log DROP CONSTRAINT audit_log_action_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check CHECK (action IN (
    'rule_create', 'rule_update', 'rule_patch', 'rule_delete',
    'device_revoke', 'device_restore', 'device_token_rotate',
    'credential_create', 'credential_revoke',
    'user_create', 'user_update', 'user_password_reset'));

ALTER TABLE audit_log DROP CONSTRAINT audit_log_target_type_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_target_type_check CHECK (target_type IN ('rule', 'device', 'user', 'credential'));