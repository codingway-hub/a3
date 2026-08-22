-- 回滚 0001_init：按依赖逆序清除索引与五张业务表。
-- 索引随表删除本会级联消失，此处显式 IF EXISTS 以保证幂等与意图清晰；
-- schema_migrations 为迁移器簿记表，不属业务 Schema，由迁移器自身管理。

DROP INDEX IF EXISTS idx_sessions_started;
DROP INDEX IF EXISTS idx_events_session;
DROP INDEX IF EXISTS idx_events_occurred;
DROP INDEX IF EXISTS idx_alerts_created;
DROP INDEX IF EXISTS idx_alerts_status;

DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS devices;
