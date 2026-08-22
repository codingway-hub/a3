-- a3 初始模型：设备、会话、事件、告警、规则五张业务表及内置规则种子。
--
-- 约定：
--   - 本文件不含 BEGIN/COMMIT，事务由迁移器（internal/server/store.Migrate）包裹，
--     保证单个迁移文件的原子应用；
--   - 正则位于标准字符串字面量内（standard_conforming_strings=on），反斜杠即字面量，
--     单引号以 '' 转义；JSON 文本内的正则反斜杠按 JSON 规则写成 \\；
--   - 种子数据以 ON CONFLICT (id) DO NOTHING 幂等写入。

-- ---------------------------------------------------------------------------
-- devices：已注册的受控终端；token_hash 为明文设备 Token 的 sha256 摘要。
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id     TEXT NOT NULL UNIQUE,
    token_hash    TEXT NOT NULL UNIQUE,
    hostname      TEXT NOT NULL DEFAULT '',
    os            TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    plugins       JSONB NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'active',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- sessions：按 (device_id, session_key) 维度聚合的事件会话摘要。
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   TEXT NOT NULL REFERENCES devices(device_id),
    agent_type  TEXT NOT NULL,
    session_key TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ NOT NULL,
    ended_at    TIMESTAMPTZ NOT NULL,
    event_count INT NOT NULL DEFAULT 0,
    risk_count  INT NOT NULL DEFAULT 0,
    UNIQUE (device_id, session_key)
);

CREATE INDEX idx_sessions_started ON sessions (started_at DESC);

-- ---------------------------------------------------------------------------
-- events：逐条上报的标准事件，payload 为完整事件 JSON。
-- ---------------------------------------------------------------------------
CREATE TABLE events (
    event_id    TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    session_key TEXT NOT NULL,
    agent_type  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL,
    payload     JSONB NOT NULL,
    risk_tags   JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_session ON events (device_id, session_key, occurred_at);
CREATE INDEX idx_events_occurred ON events (occurred_at DESC);

-- ---------------------------------------------------------------------------
-- alerts：规则命中产生的告警及其处置状态。
-- ---------------------------------------------------------------------------
CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       TEXT NOT NULL,
    session_key     TEXT NOT NULL DEFAULT '',
    event_id        TEXT NOT NULL DEFAULT '',
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    action          TEXT NOT NULL,
    snippet         TEXT NOT NULL DEFAULT '',
    summary         TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ
);

CREATE INDEX idx_alerts_created ON alerts (created_at DESC);
CREATE INDEX idx_alerts_status ON alerts (status);

-- ---------------------------------------------------------------------------
-- rules：风险识别规则；matcher 形状统一为
-- {"target":"any|command|path","patterns":["正则"...],"path_globs":["glob"...]}
-- （path 类规则用 path_globs，其余用 patterns）。
-- ---------------------------------------------------------------------------
CREATE TABLE rules (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    category   TEXT NOT NULL,
    matcher    JSONB NOT NULL,
    severity   TEXT NOT NULL,
    action     TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    builtin    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- 内置规则种子（14 条）：与终端 plugin-claude 预置规则同源清单，幂等写入。
-- ---------------------------------------------------------------------------
INSERT INTO rules (id, name, category, matcher, severity, action)
SELECT seed.id, seed.name, seed.category, seed.matcher::jsonb, seed.severity, seed.action
FROM (VALUES
    ('dlp.aws_access_key', 'AWS AccessKey 泄露', 'dlp',
     '{"target":"any","patterns":["\\bAKIA[0-9A-Z]{16}\\b"]}', 'high', 'block'),
    ('dlp.aws_secret_key', 'AWS SecretKey 泄露', 'dlp',
     '{"target":"any","patterns":["(?i)aws.{0,20}[''\"][0-9a-zA-Z/+]{40}[''\"]"]}', 'high', 'block'),
    ('dlp.private_key_block', '私钥文件内容泄露', 'dlp',
     '{"target":"any","patterns":["-----BEGIN [A-Z ]*PRIVATE KEY-----"]}', 'high', 'block'),
    ('dlp.generic_api_key', '通用 API 密钥泄露', 'dlp',
     '{"target":"any","patterns":["(?i)\\b(api[_-]?key|secret[_-]?key|access[_-]?token)\\b\\s*[:=]\\s*[''\"]?[A-Za-z0-9_\\-/.+]{16,}"]}', 'high', 'block'),
    ('dlp.jwt', 'JWT 令牌泄露', 'dlp',
     '{"target":"any","patterns":["\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{5,}\\b"]}', 'high', 'block'),
    ('dlp.db_conn_string', '数据库连接串凭证泄露', 'dlp',
     '{"target":"any","patterns":["(?i)(postgres(?:ql)?|mysql|mongodb(\\+srv)?|redis)://[^\\s:@]+:[^\\s@]+@"]}', 'high', 'block'),
    ('cmd.rm_rf_root', '高危递归强删(rm -rf 根/家目录)', 'cmd',
     '{"target":"command","patterns":["\\brm\\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\\s+(--\\s+)?(/|~|\\*)","\\brm\\s+/.*\\s+-[a-zA-Z]*r[a-zA-Z]*f"]}', 'high', 'block'),
    ('cmd.git_force_push', 'Git 强制推送', 'cmd',
     '{"target":"command","patterns":["git\\s+push[^|;&]*(--force\\b|--force-with-lease\\b|--delete\\b)"]}', 'high', 'block'),
    ('cmd.remote_script_exec', '远程脚本管道执行', 'cmd',
     '{"target":"command","patterns":["(curl|wget)[^|]*\\|\\s*(sudo\\s+)?(ba|z|da|)sh\\b"]}', 'high', 'block'),
    ('cmd.chmod_privilege', '全权限放开(chmod 777 系统路径)', 'cmd',
     '{"target":"command","patterns":["chmod\\s+(-R\\s+)?[0-7]*7[0-7]*7\\s+/"]}', 'high', 'block'),
    ('cmd.disk_wipe', '磁盘抹写/格式化', 'cmd',
     '{"target":"command","patterns":["(mkfs\\.\\w+\\s|dd\\s+if=[^ ]*\\s+of=/dev/)"]}', 'high', 'block'),
    ('file.ssh_private_read', '敏感私钥文件访问', 'file',
     '{"target":"path","path_globs":["~/.ssh/*","*.pem","id_rsa*"]}', 'high', 'block'),
    ('file.dotenv_access', '环境变量文件访问', 'file',
     '{"target":"path","path_globs":[".env","*.env"]}', 'high', 'alert'),
    ('git.history_rewrite', 'Git 历史重写', 'git',
     '{"target":"command","patterns":["git\\s+(reset\\s+--hard|filter-branch|filter-repo|rebase\\s+--root)"]}', 'medium', 'alert')
) AS seed(id, name, category, matcher, severity, action)
ON CONFLICT (id) DO NOTHING;
