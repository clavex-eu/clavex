-- Browser sessions table for Forward Auth Proxy
-- Separate from OIDC refresh_tokens: these are long-lived browser cookies.
CREATE TABLE IF NOT EXISTS browser_sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    session_hash TEXT NOT NULL UNIQUE,  -- SHA-256 of the cookie value
    user_agent   TEXT,
    ip_address   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_browser_sessions_user_id ON browser_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_browser_sessions_org_id  ON browser_sessions(org_id);
