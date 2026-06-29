-- 000094_audit_siem_sinks.down.sql
-- Note: rows using 'splunk_hec' or 'sentinel' must be deleted before rolling back.
ALTER TABLE audit_sinks
    DROP CONSTRAINT IF EXISTS audit_sinks_sink_type_check;

ALTER TABLE audit_sinks
    ADD CONSTRAINT audit_sinks_sink_type_check
        CHECK (sink_type IN ('webhook','http','mqtt','kafka'));
