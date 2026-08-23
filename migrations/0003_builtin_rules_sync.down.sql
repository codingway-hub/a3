-- 还原 cmd.rm_rf_root / cmd.git_force_push 为 0001 初版种子值。
INSERT INTO rules (id, name, category, matcher, severity, action)
SELECT seed.id, seed.name, seed.category, seed.matcher::jsonb, seed.severity, seed.action
FROM (VALUES
    ('cmd.rm_rf_root', '高危递归强删(rm -rf 根/家目录)', 'cmd',
     '{"target":"command","patterns":["\\brm\\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\\s+(--\\s+)?(/|~|\\*)","\\brm\\s+/.*\\s+-[a-zA-Z]*r[a-zA-Z]*f"]}', 'high', 'block'),
    ('cmd.git_force_push', 'Git 强制推送', 'cmd',
     '{"target":"command","patterns":["git\\s+push[^|;&]*(--force\\b|--force-with-lease\\b|--delete\\b)"]}', 'high', 'block')
) AS seed(id, name, category, matcher, severity, action)
ON CONFLICT (id) DO UPDATE SET
    name       = EXCLUDED.name,
    category   = EXCLUDED.category,
    matcher    = EXCLUDED.matcher,
    severity   = EXCLUDED.severity,
    action     = EXCLUDED.action,
    updated_at = now()
WHERE rules.builtin;
