-- 0013: 会话撤销能力 + 设备 Token 有效期 + 设备禁用态。
--
-- 1) 管理员 JWT 可撤销：admin_users.token_version 代际号。账号停用/改角色/重置口令
--    时自增，登录签发的 JWT 携带签发时的 ver，鉴权中间件比对当前库内版本——
--    停用/降级不再需要等到 JWT 自然过期（≤8h）才生效。
-- 2) 设备 Token 有效期：devices.token_expires_at 为空表示永久（默认）。部署方配置
--    A3_DEVICE_TOKEN_TTL_HOURS 后，注册/管理员换发时落到期时间，鉴权中间件对
--    过期 Token 一律 401（设备需重新注册或由管理员换发）。
-- 3) 设备禁用态 disabled（区别于 revoked）：临时挂起、身份保留、不可自助重注册，
--    恢复仅管理员可操作；audit_log 的 action 扩入 device_disable 语义。

ALTER TABLE admin_users ADD COLUMN token_version BIGINT NOT NULL DEFAULT 0;

ALTER TABLE devices ADD COLUMN token_expires_at TIMESTAMPTZ NULL;

-- audit_log 的 action CHECK 扩入 device_disable（0011 曾重建过此约束，此处镜像其全集）
ALTER TABLE audit_log DROP CONSTRAINT audit_log_action_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check CHECK (action IN (
    'rule_create', 'rule_update', 'rule_patch', 'rule_delete',
    'device_revoke', 'device_disable', 'device_restore', 'device_token_rotate',
    'credential_create', 'credential_revoke',
    'user_create', 'user_update', 'user_password_reset'));