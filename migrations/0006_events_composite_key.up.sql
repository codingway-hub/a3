-- 0006: events 主键改为 (device_id, event_id) 复合唯一。
--
-- 背景：event_id 原为全局主键，跨设备上报同 event_id（如终端确定性派生的
-- 事件 ID）时 ON CONFLICT DO NOTHING 会静默吞掉第二台设备的证据（审计缺失）。
-- 改为设备内的复合唯一：设备内重放幂等保留，跨设备同 ID 各自落库（证据无损）。
-- 已核实 alerts.event_id 为无外键的普通列，events 无其他外键引用，迁移安全。

ALTER TABLE events DROP CONSTRAINT events_pkey;
ALTER TABLE events ADD CONSTRAINT events_pkey PRIMARY KEY (device_id, event_id);