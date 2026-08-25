DROP INDEX IF EXISTS idx_events_unscanned;
ALTER TABLE events DROP COLUMN IF EXISTS scanned_at;
