-- Clavex Shield: persist threat-intel verdict per login event.
-- Columns are NULL when Shield is not configured or the IP is private/loopback.
ALTER TABLE login_history
    ADD COLUMN IF NOT EXISTS is_malicious    BOOLEAN  DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS confidence_score SMALLINT DEFAULT NULL,   -- AbuseIPDB 0-100
    ADD COLUMN IF NOT EXISTS is_tor_exit     BOOLEAN  DEFAULT NULL;

-- Fast aggregation for the Shield dashboard (blocked IPs, Tor trend).
CREATE INDEX IF NOT EXISTS idx_login_history_shield
    ON login_history (org_id, created_at DESC)
    WHERE is_malicious = TRUE;
