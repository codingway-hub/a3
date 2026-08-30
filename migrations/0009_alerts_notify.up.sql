-- 0009: 告警通知外送进度标记。
--
-- notified_at 记录告警成功外送到通知渠道（webhook）的时刻，NULL 表示尚未外送；
-- notify_attempts 记录外送失败次数，达到上限后轮询查询不再返回该行（坏 URL 自然老化）。
-- 存量数据统一回填为已通知（照 0004 先例）：启用外送前的历史告警不补发，
-- 避免首次启用时向 webhook 收端倾泻全量历史告警。
--
-- 外送语义为 at-least-once：发送成功与标记落库之间进程崩溃会产生重复通知，可接受。

ALTER TABLE alerts ADD COLUMN notified_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN notify_attempts INT NOT NULL DEFAULT 0;

-- 部分索引：通知轮询查询（notified_at IS NULL）专用（照 idx_events_unscanned 先例）
CREATE INDEX idx_alerts_unnotified ON alerts (created_at) WHERE notified_at IS NULL;

UPDATE alerts SET notified_at = now() WHERE notified_at IS NULL;
