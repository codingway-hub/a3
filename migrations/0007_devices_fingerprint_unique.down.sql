-- 0007 down：还原为普通指纹索引（best-effort）。
-- 若已有同指纹多行 active（部分唯一索引期间的合法状态），还原后也不违反约束，安全。

DROP INDEX IF EXISTS idx_devices_fingerprint_active;
CREATE INDEX idx_devices_fingerprint ON devices (machine_fingerprint);