-- 0006 down：还原为全局 event_id 主键（best-effort）。
-- 若已存在跨设备同 event_id 数据，此还原会因违反唯一性而失败，属预期防护。

ALTER TABLE events DROP CONSTRAINT events_pkey;
ALTER TABLE events ADD CONSTRAINT events_pkey PRIMARY KEY (event_id);