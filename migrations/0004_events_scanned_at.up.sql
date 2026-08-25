-- 0004: 服务端扫描无损化：为 events 增加 scanned_at 扫描进度列。
--
-- scanned_at 记录事件完成服务端规则扫描的时刻，NULL 表示尚未扫描。
-- 有了显式进度标记，"干净"与"还没扫到"不再共用 risk_tags='[]' 一个形状，
-- 队列满丢弃、进程重启丢内存队列、引擎未就绪失败等造成的漏扫积压
-- 都能由告警中心按 scanned_at IS NULL 对账捞回补扫（最终无损）。
--
-- 存量数据统一回填为已扫描：历史事件不补扫，避免旧规则重复产生大量告警；
-- 无损语义自本版本起对新增事件生效。

ALTER TABLE events ADD COLUMN scanned_at TIMESTAMPTZ;

CREATE INDEX idx_events_unscanned ON events (occurred_at) WHERE scanned_at IS NULL;

UPDATE events SET scanned_at = now() WHERE scanned_at IS NULL;
