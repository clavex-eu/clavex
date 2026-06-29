-- Magic link tokens
CREATE TABLE IF NOT EXISTS magic_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    user_id      UUID REFERENCES identity.users(id) ON DELETE CASCADE,
    email        TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    -- 'login' = passwordless first factor, 'mfa' = second factor fallback
    purpose      TEXT NOT NULL DEFAULT 'login',
    -- auth_req_key ties the magic link to an in-progress OIDC session (Redis key)
    auth_req_key TEXT,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_magic_links_org_id     ON magic_links(org_id);
CREATE INDEX IF NOT EXISTS idx_magic_links_token_hash ON magic_links(token_hash);

-- Per-org magic link settings (columns on organizations)
ALTER TABLE identity.organizations
    ADD COLUMN IF NOT EXISTS magic_link_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS magic_link_as_mfa   BOOLEAN NOT NULL DEFAULT FALSE;
