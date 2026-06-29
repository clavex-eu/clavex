-- 000094_audit_siem_sinks.up.sql
-- Extend the audit_sinks.sink_type CHECK constraint to allow the two new
-- SIEM sink types: splunk_hec (Splunk HTTP Event Collector) and sentinel
-- (Microsoft Sentinel / Log Analytics Data Collector API).

ALTER TABLE audit_sinks
    DROP CONSTRAINT IF EXISTS audit_sinks_sink_type_check;

ALTER TABLE audit_sinks
    ADD CONSTRAINT audit_sinks_sink_type_check
        CHECK (sink_type IN ('webhook','http','mqtt','kafka','splunk_hec','sentinel'));
