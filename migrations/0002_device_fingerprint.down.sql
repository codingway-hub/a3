-- 回滚设备指纹列。

DROP INDEX IF EXISTS idx_devices_fingerprint;
ALTER TABLE devices DROP COLUMN IF EXISTS machine_fingerprint;
