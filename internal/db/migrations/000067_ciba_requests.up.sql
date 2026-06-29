-- 000067_ciba_requests: stores Client-Initiated Backchannel Authentication
-- requests (OpenID Connect CIBA Core 1.0 — poll delivery mode).
--
-- Lifecycle:
--   pending   → the backchannel request was accepted; the client polls /token
--   approved  → the end-user approved the request; next poll returns tokens
--   denied    → the end-user denied; next poll returns access_denied
--
-- Expired requests are cleaned up by a background worker via expires_at.
-- The `interval` column holds the minimum polling interval in seconds
-- (default 5 per CIBA Core §7.3).
CREATE TABLE IF NOT EXISTS ciba_requests (
    auth_req_id     TEXT        PRIMARY KEY,
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_id       TEXT        NOT NULL,
    user_id         UUID        REFERENCES users(id) ON DELETE CASCADE,
    scope           TEXT        NOT NULL DEFAULT '',
    binding_message TEXT,
    login_hint      TEXT,
    status          TEXT        NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'denied')),
    interval        INT         NOT NULL DEFAULT 5,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ciba_requests_org_status ON ciba_requests (org_id, status);
CREATE INDEX IF NOT EXISTS idx_ciba_requests_expires    ON ciba_requests (expires_at);
