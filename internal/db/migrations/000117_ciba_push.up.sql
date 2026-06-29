-- 000117_ciba_push: native mobile push notification support for CIBA.
--
-- Two parts:
--   1. APNs/FCM delivery credentials on the per-org notification config.
--   2. ciba_device_tokens table: user-registered push tokens (one row per
--      user+org+platform+device_token).  The CIBA notification dispatcher
--      looks these up at delivery time.

-- ── 1. Push credentials on org_ciba_notification_config ─────────────────────

ALTER TABLE org_ciba_notification_config
    -- Whether to deliver push notifications (requires at least one of
    -- apns_* or fcm_service_account_json to be configured).
    ADD COLUMN IF NOT EXISTS push_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    -- Apple Push Notification service (HTTP/2 provider-token auth)
    -- apns_key_p8: PEM content of the .p8 file (PKCS#8 EC private key).
    ADD COLUMN IF NOT EXISTS apns_key_p8         TEXT,
    -- 10-character key identifier from the Apple Developer portal.
    ADD COLUMN IF NOT EXISTS apns_key_id         TEXT,
    -- Apple Developer team ID (10-character string).
    ADD COLUMN IF NOT EXISTS apns_team_id        TEXT,
    -- App bundle ID used as the APNs topic (e.g. "com.example.banking").
    ADD COLUMN IF NOT EXISTS apns_bundle_id      TEXT,
    -- true → production APNs; false → sandbox (default false for safety).
    ADD COLUMN IF NOT EXISTS apns_production     BOOLEAN NOT NULL DEFAULT FALSE,

    -- Firebase Cloud Messaging v1 API (service account JSON key)
    -- Full JSON content of the Google service account key file.
    -- Contains: project_id, client_email, private_key (RSA PEM).
    ADD COLUMN IF NOT EXISTS fcm_service_account_json TEXT;

-- ── 2. ciba_device_tokens ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ciba_device_tokens (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- "apns" or "fcm"
    platform     TEXT        NOT NULL CHECK (platform IN ('apns', 'fcm')),
    -- The opaque push token string returned by the OS SDK.
    device_token TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One row per (org, user, platform, token) — re-registering the same token
    -- is a no-op (ON CONFLICT … DO UPDATE updated_at).
    UNIQUE (org_id, user_id, platform, device_token)
);

CREATE INDEX IF NOT EXISTS idx_ciba_device_tokens_org_user
    ON ciba_device_tokens (org_id, user_id);

-- Trigger to keep updated_at current.
CREATE OR REPLACE FUNCTION update_ciba_device_tokens_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

CREATE TRIGGER trg_ciba_device_tokens_updated_at
    BEFORE UPDATE ON ciba_device_tokens
    FOR EACH ROW EXECUTE FUNCTION update_ciba_device_tokens_updated_at();
