-- 还原：回收 alerts 上的直接标记列，把 outbox 投递结果回填回去。
ALTER TABLE alerts ADD COLUMN notified_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN notify_attempts INT NOT NULL DEFAULT 0;
CREATE INDEX idx_alerts_unnotified ON alerts (created_at) WHERE notified_at IS NULL;

UPDATE alerts a
   SET notified_at = outbox.sent_at,
       notify_attempts = outbox.attempts
  FROM notification_outbox outbox
 WHERE outbox.alert_id = a.id
   AND a.notified_at IS NULL;

DROP TABLE notification_outbox;