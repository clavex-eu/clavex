-- 000013_smtp_settings.up.sql
-- Per-org SMTP server configuration for transactional emails
CREATE TABLE org_smtp_settings (
    org_id           UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    host             TEXT NOT NULL,
    port             INT  NOT NULL DEFAULT 587,
    username         TEXT,
    password         TEXT,                    -- stored encrypted (AES-GCM via config key)
    from_address     TEXT NOT NULL,
    from_name        TEXT NOT NULL DEFAULT 'Clavex',
    use_tls          BOOL NOT NULL DEFAULT TRUE,
    is_active        BOOL NOT NULL DEFAULT FALSE,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
