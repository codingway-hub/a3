-- 告警通知 outbox：每次外送的持久队列 + 投递状态，替换 alerts.notified_at / notify_attempts
-- 的「标记在告警行」模型。
--
-- 可靠性要点：
--   - 入队与告警落库同事务（ApplyScanOutcome / CreateAlert），进程崩溃不丢通知；
--   - 去重靠唯一 dedup_key（= 告警 ID）判等，同一告警至多一条通知；
--   - 投递状态逐条在库：pending → sending → sent｜failed（退避后可重试）｜dropped（次数封顶）；
--   - 重试退避按行调度：next_attempt_at 之后才可再次被领取；sending 超时（10 分钟）视为
--     领取方崩溃的孤儿行，下轮可回收。
CREATE TABLE notification_outbox (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    dedup_key       text NOT NULL UNIQUE,
    alert_id        uuid NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'dropped')),
    attempts        int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text,
    sent_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- 领取查询专用索引：到期待发（pending/failed）与回收孤儿（sending 悬挂）
CREATE INDEX idx_outbox_due     ON notification_outbox (next_attempt_at) WHERE status IN ('pending', 'failed');
CREATE INDEX idx_outbox_sending ON notification_outbox (updated_at)      WHERE status = 'sending';

-- 旧模型索引随通知列一起下线：先删索引再删列（删列会连带隐式删掉
-- 引用 notified_at 的部分索引，此处显式删除并 IF EXISTS 兜底防重复执行）。
DROP INDEX IF EXISTS idx_alerts_unnotified;

-- 既有告警迁移到 outbox：已外送 → sent；失败达 10 次 → dropped（与历史上限一致）；
-- 其余保留 pending，保留既有的失败次数以便退避续跑。
INSERT INTO notification_outbox (dedup_key, alert_id, status, attempts, sent_at, created_at, updated_at)
SELECT id::text, id,
       CASE WHEN notified_at IS NOT NULL              THEN 'sent'
            WHEN notify_attempts >= 10               THEN 'dropped'
            ELSE 'pending' END,
       notify_attempts, notified_at, created_at, created_at
FROM alerts;

ALTER TABLE alerts DROP COLUMN notified_at;
ALTER TABLE alerts DROP COLUMN notify_attempts;