-- 000137_compliance_drift.up.sql
-- NIS2 / zero-trust compliance drift detection.
--
-- Two tables:
--   compliance_snapshots  — latest security fingerprint per org (upserted each scan)
--   compliance_drift_events — immutable audit log of detected control changes

CREATE TABLE IF NOT EXISTS compliance_snapshots (
    org_id       UUID        NOT NULL PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    snapshot     JSONB       NOT NULL,
    snapshot_hash TEXT       NOT NULL,
    captured_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_drift_events (
    id             UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    control        TEXT        NOT NULL, -- e.g. "mfa_required", "access_token_ttl"
    previous_value TEXT,
    current_value  TEXT,
    severity       TEXT        NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    detected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS compliance_drift_events_org_at
    ON compliance_drift_events (org_id, detected_at DESC);
