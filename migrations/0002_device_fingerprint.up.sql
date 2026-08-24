-- 设备表补充机器指纹列：支撑"同指纹重复注册返回既有设备"的幂等注册语义。
-- 指纹由终端生成（hostname+mac 哈希），服务端不解析其构成。

ALTER TABLE devices ADD COLUMN machine_fingerprint TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_devices_fingerprint ON devices (machine_fingerprint);
