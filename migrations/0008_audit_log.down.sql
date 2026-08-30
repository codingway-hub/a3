-- 0008 回滚：删除规则审计留痕（down 尽力而为；已产生的审计记录随表删除）。

ALTER TABLE rules DROP COLUMN updated_by;

DROP INDEX IF EXISTS audit_log_created_idx;
DROP INDEX IF EXISTS audit_log_target_idx;
DROP TABLE IF EXISTS audit_log;
