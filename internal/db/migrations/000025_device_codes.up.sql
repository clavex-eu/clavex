-- RFC 8628 Device Authorization Grant
CREATE TABLE IF NOT EXISTS device_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL,
    device_code_hash TEXT NOT NULL UNIQUE,
    user_code       TEXT NOT NULL UNIQUE,
    scope           TEXT NOT NULL DEFAULT '',
    -- NULL=pending, TRUE=authorized, FALSE=denied
    is_authorized   BOOLEAN,
    user_id         UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    last_polled_at  TIMESTAMPTZ,
    poll_interval   INTEGER NOT NULL DEFAULT 5,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_codes_org_id    ON device_codes(org_id);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
