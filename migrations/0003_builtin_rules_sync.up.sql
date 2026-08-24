-- 内置规则种子修正：与终端 BuiltinRules 对齐（internal/agent/plugins/claude/rules.go）。
-- cmd.rm_rf_root 统一为终端单正则；cmd.git_force_push 类别归位 git。
-- 幂等 upsert；不触碰 enabled 字段；DO UPDATE 仅作用于 builtin 行。

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
     '{"target":"any","patterns":["(?i)\\b(api[_-]?key|secret[_-]?key|access[_-]?token)\\b\\s*[:=]\\s*[\"'']?[A-Za-z0-9_\\-/.+]{16,}"]}', 'high', 'block'),
    ('dlp.jwt', 'JWT 令牌泄露', 'dlp',
     '{"target":"any","patterns":["\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{5,}\\b"]}', 'high', 'block'),
    ('dlp.db_conn_string', '数据库连接串凭证泄露', 'dlp',
     '{"target":"any","patterns":["(?i)(postgres(?:ql)?|mysql|mongodb(\\+srv)?|redis)://[^\\s:@]+:[^\\s@]+@"]}', 'high', 'block'),
    ('cmd.rm_rf_root', '高危递归强删(rm -rf 根/家目录)', 'cmd',
     '{"target":"command","patterns":["\\brm\\s+(?:-{1,2}[\\w=-]+\\s+)*(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\\s+\"?(?:/|~|\\*)"]}', 'high', 'block'),
    ('cmd.git_force_push', 'Git 强制推送', 'git',
     '{"target":"command","patterns":["git\\s+push[^|;&]*(--force\\b|--force-with-lease|--delete\\b)"]}', 'high', 'block'),
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
ON CONFLICT (id) DO UPDATE SET
    name     = EXCLUDED.name,
    category = EXCLUDED.category,
    matcher  = EXCLUDED.matcher,
    severity = EXCLUDED.severity,
    action   = EXCLUDED.action,
    updated_at = now()
WHERE rules.builtin;