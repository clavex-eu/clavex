-- 000033_login_history_rate_limits.up.sql
-- Persistent login history (event-sourced authentication events) and per-org
-- rate-limit configuration.

-- ── Login history ─────────────────────────────────────────────────────────────
-- Immutable append-only table: every authentication attempt (success or failure)
-- is recorded here. This is the foundation for anomaly detection, DSAR exports,
-- and NIS2 incident reporting.
CREATE TABLE login_history (
    id              BIGSERIAL   PRIMARY KEY,
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID        REFERENCES users(id) ON DELETE SET NULL,
    -- Snapshot of email at the time of the attempt (preserved even if user deleted)
    email           TEXT,
    -- "password" | "totp" | "webauthn" | "magic_link" | "idp" | "spid" | "cie" | "device"
    auth_method     TEXT        NOT NULL DEFAULT 'password',
    -- "success" | "failure"
    status          TEXT        NOT NULL CHECK (status IN ('success', 'failure')),
    -- Reason for failure (e.g. "invalid_password", "user_inactive", "mfa_failed")
    failure_reason  TEXT,
    ip_address      INET,
    user_agent      TEXT,
    -- ISO 3166-1 alpha-2, populated by server-side geo-IP lookup (optional)
    country_code    CHAR(2),
    city            TEXT,
    -- ASN organisation (e.g. "AS15169 Google LLC") for VPN/datacenter detection
    asn_org         TEXT,
    -- The OIDC client that triggered the login (null for direct API logins)
    client_id       TEXT        REFERENCES oidc_clients(client_id) ON DELETE SET NULL,
    session_id      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Queries: list by user (profile page, DSAR export), list by org (security dashboard)
CREATE INDEX idx_login_history_user    ON login_history(user_id, created_at DESC)
    WHERE user_id IS NOT NULL;
CREATE INDEX idx_login_history_org     ON login_history(org_id, created_at DESC);
-- Anomaly detection: distinct countries per user in a rolling window
CREATE INDEX idx_login_history_country ON login_history(user_id, country_code, created_at DESC)
    WHERE user_id IS NOT NULL AND country_code IS NOT NULL;
-- Brute-force detection: failures from a given IP
CREATE INDEX idx_login_history_ip_fail ON login_history(org_id, ip_address, created_at DESC)
    WHERE status = 'failure';

-- ── Per-org rate limit configuration ─────────────────────────────────────────
-- Allows platform admins to configure different rate limits per tenant.
-- The actual enforcement uses Redis sliding-window counters in the middleware;
-- this table is the source of truth that is cached per request.
CREATE TABLE org_rate_limits (
    org_id              UUID    PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    -- Maximum login attempts per IP per minute on this org's auth endpoints
    login_per_ip_per_min    INT NOT NULL DEFAULT 10,
    -- Maximum token requests per client_id per minute
    token_per_client_per_min INT NOT NULL DEFAULT 60,
    -- Absolute limit on any single IP hitting any tenant endpoint per minute
    global_per_ip_per_min   INT NOT NULL DEFAULT 120,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default rate limits for existing orgs so the table is never empty for them.
INSERT INTO org_rate_limits (org_id)
SELECT id FROM organizations
ON CONFLICT (org_id) DO NOTHING;

-- Also update last_login_at by triggering on login_history INSERT (success only).
-- This keeps the denormalised column on users in sync without changing every login
-- code path — the trigger handles it automatically.
CREATE OR REPLACE FUNCTION sync_last_login_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'success' AND NEW.user_id IS NOT NULL THEN
        UPDATE users
        SET last_login_at = NEW.created_at
        WHERE id = NEW.user_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_sync_last_login_at
AFTER INSERT ON login_history
FOR EACH ROW EXECUTE FUNCTION sync_last_login_at();
