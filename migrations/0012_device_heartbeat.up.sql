-- 设备心跳与数据滞留信号：终端常驻心跳上报其本地 spool 积压，
-- 服务端据此把设备区分为 online（在线无积压）/ abnormal（在线但数据滞留）/ offline（超时无心跳）。

ALTER TABLE devices
    ADD COLUMN spool_pending_batches BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN spool_pending_bytes   BIGINT NOT NULL DEFAULT 0;