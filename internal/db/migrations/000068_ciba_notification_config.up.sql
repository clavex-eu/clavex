-- 000068_ciba_notification_config: per-org configuration for CIBA push
-- notifications delivered when a backchannel authentication request is created.
--
-- Channels:
--   webhook  — HTTP POST to a configured URL (HMAC-SHA256 signed)
--   email    — transactional email via the org's SMTP settings
--   sms      — SMS via the org's configured SMS provider
--
-- Only one row per org (singleton enforced by PRIMARY KEY on org_id).
-- All channel fields are nullable; a NULL means that channel is disabled.
-- The notification config is optional — if no row exists for an org, CIBA
-- requests are accepted but no notification is sent (admin-console-only flow).
CREATE TABLE IF NOT EXISTS org_ciba_notification_config (
    org_id              UUID        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,

    -- Webhook channel ---------------------------------------------------
    -- URL that receives an HMAC-signed JSON POST for every CIBA request.
    -- Must be HTTPS in production.
    webhook_url         TEXT,
    -- HMAC-SHA256 signing secret. NULL = no signature header.
    webhook_secret      TEXT,
    -- Extra HTTP headers forwarded with every webhook request (JSON object).
    -- Example: {"Authorization": "Bearer <token>"}
    webhook_headers     JSONB       NOT NULL DEFAULT '{}',

    -- Email channel -----------------------------------------------------
    -- Whether to send an approval email via the org's SMTP settings.
    -- Requires org_smtp_settings to be configured and active.
    email_enabled       BOOLEAN     NOT NULL DEFAULT FALSE,

    -- SMS channel -------------------------------------------------------
    -- Whether to send an approval SMS via the org's SMS provider.
    -- Requires org_sms_settings to be configured and active.
    sms_enabled         BOOLEAN     NOT NULL DEFAULT FALSE,

    -- Base URL used to construct approve/deny deep links.
    -- Example: "https://auth.example.com/ciba"
    -- If NULL, the Clavex server's own API URL is used.
    -- The handler appends "/<auth_req_id>/approve" and "/<auth_req_id>/deny".
    base_url            TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trigger to keep updated_at current.
CREATE OR REPLACE FUNCTION update_ciba_notification_config_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

CREATE TRIGGER trg_ciba_notification_config_updated_at
    BEFORE UPDATE ON org_ciba_notification_config
    FOR EACH ROW EXECUTE FUNCTION update_ciba_notification_config_updated_at();
