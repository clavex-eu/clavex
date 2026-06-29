CREATE TABLE IF NOT EXISTS org_invitations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role_id     UUID REFERENCES identity.roles(id) ON DELETE SET NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    invited_by  UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    accepted_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_invitations_org_id    ON org_invitations(org_id);
CREATE INDEX IF NOT EXISTS idx_org_invitations_email     ON org_invitations(email);
CREATE INDEX IF NOT EXISTS idx_org_invitations_token     ON org_invitations(token_hash);
