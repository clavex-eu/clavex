-- 030_audit_structured.down.sql
DROP INDEX IF EXISTS idx_audit_sinks_org;
DROP TABLE IF EXISTS audit_sinks;
DROP TABLE IF EXISTS audit_retention;

DROP INDEX IF EXISTS idx_audit_session;
DROP INDEX IF EXISTS idx_audit_status;
DROP INDEX IF EXISTS idx_audit_resource;
DROP INDEX IF EXISTS idx_audit_action;
DROP INDEX IF EXISTS idx_audit_org_cursor;
DROP INDEX IF EXISTS idx_audit_event_id;

ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS dispatched_at,
    DROP COLUMN IF EXISTS data_schema,
    DROP COLUMN IF EXISTS country_code,
    DROP COLUMN IF EXISTS request_id,
    DROP COLUMN IF EXISTS session_id,
    DROP COLUMN IF EXISTS subject,
    DROP COLUMN IF EXISTS event_type,
    DROP COLUMN IF EXISTS event_source,
    DROP COLUMN IF EXISTS spec_version,
    DROP COLUMN IF EXISTS event_id;
