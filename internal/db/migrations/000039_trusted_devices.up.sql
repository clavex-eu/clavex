CREATE TABLE IF NOT EXISTS trusted_devices (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- HMAC-SHA256(device_trust_secret, device_token + ":" + user_id)
    fingerprint_hash TEXT NOT NULL,
    display_name     TEXT,           -- e.g. "Chrome 124 on macOS 14"
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, user_id, fingerprint_hash)
);

CREATE INDEX IF NOT EXISTS idx_trusted_devices_user_id ON trusted_devices(user_id);
