-- GDPR Art.5(1)(e) per-org user data retention and auto-anonymisation policy.
-- When enabled, a background worker anonymises users whose last activity
-- (last_login_at or updated_at, depending on activity_field) is older than
-- retention_days. PII is replaced with placeholder values; the audit trail
-- and the UUID are preserved so historical log entries stay meaningful.
--
-- exempt_role_names: users that hold ANY of these role names are never anonymised.

CREATE TABLE org_gdpr_retention (
    org_id             uuid        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    retention_days     int         NOT NULL DEFAULT 730,    -- default: 2 years
    activity_field     text        NOT NULL DEFAULT 'last_login_at',  -- or 'updated_at'
    exempt_role_names  text[]      NOT NULL DEFAULT '{}',
    enabled            boolean     NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
