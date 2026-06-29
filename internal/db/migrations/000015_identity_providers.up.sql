-- 000015_identity_providers.up.sql
-- External OAuth2 / OIDC identity providers (Social Login / SSO federation).
-- Supported types: 'oidc' | 'google' | 'github' | 'microsoft' | 'gitlab'
CREATE TABLE identity_providers (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,                -- display name, e.g. "Google Workspace"
    provider_type         TEXT NOT NULL DEFAULT 'oidc', -- oidc | google | github | microsoft | gitlab
    client_id             TEXT NOT NULL,
    client_secret         TEXT NOT NULL,                -- stored encrypted
    authorization_url     TEXT NOT NULL,
    token_url             TEXT NOT NULL,
    userinfo_url          TEXT,
    scopes                TEXT NOT NULL DEFAULT 'openid email profile',
    email_claim           TEXT NOT NULL DEFAULT 'email',
    first_name_claim      TEXT NOT NULL DEFAULT 'given_name',
    last_name_claim       TEXT NOT NULL DEFAULT 'family_name',
    is_active             BOOL NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, name)
);

CREATE INDEX idx_idp_org_id ON identity_providers(org_id);
