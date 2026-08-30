-- 0007: 设备指纹部分唯一索引——同指纹只允许一个 active 设备。
--
-- 背景：机器指纹是终端生成的幂等标识，本应唯一归属一台设备。此前仅普通索引，
-- 未约束 + 注册「查-改」非原子使同一指纹可产生多条 active 行，且恶意方仅凭指纹
-- 即可换发他人 Token（身份顶替）。部分唯一索引让吊销/历史后的行不占指纹锁，
-- 同指纹后续可重新上号（恢复路径：管理员吊销 → 重新 register 建新设备）。
--
-- 顺序关键：先兜底历史空指纹，再清理历史并发产生的重复 active 行，最后建索引。

-- (1) 兜底历史空指纹：0002 之前建立的设备 machine_fingerprint 为 ''，直接建唯一索引必失败。
UPDATE devices SET machine_fingerprint = 'legacy-' || device_id
 WHERE machine_fingerprint = '';

-- (2) 去重：每个指纹仅保留最早登记的 active 行，其余置 revoked（历史并发竞态产物）。
WITH ranked AS (
  SELECT id, row_number() OVER (PARTITION BY machine_fingerprint ORDER BY first_seen_at, id) AS rn
    FROM devices WHERE status = 'active')
UPDATE devices d SET status = 'revoked' FROM ranked r
 WHERE d.id = r.id AND r.rn > 1;

-- (3) 普通索引换部分唯一索引：active 时指纹唯一。
DROP INDEX IF EXISTS idx_devices_fingerprint;
CREATE UNIQUE INDEX idx_devices_fingerprint_active
  ON devices (machine_fingerprint) WHERE status = 'active';