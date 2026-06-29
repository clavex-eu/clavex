-- 000033_login_history_rate_limits.down.sql

DROP TRIGGER IF EXISTS trg_sync_last_login_at ON login_history;
DROP FUNCTION IF EXISTS sync_last_login_at();
DROP TABLE IF EXISTS org_rate_limits;
DROP TABLE IF EXISTS login_history;
