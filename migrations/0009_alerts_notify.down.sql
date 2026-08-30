DROP INDEX IF EXISTS idx_alerts_unnotified;
ALTER TABLE alerts DROP COLUMN IF EXISTS notify_attempts;
ALTER TABLE alerts DROP COLUMN IF EXISTS notified_at;
