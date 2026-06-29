-- 000003_oidc_tokens.up.sql

-- ─────────────────────────────────────────────
-- Authorization codes (short-lived, one-time)
-- ─────────────────────────────────────────────
CREATE TABLE authorization_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- SHA-256 of the opaque code sent to the client
    code_hash       TEXT NOT NULL UNIQUE,

    redirect_uri    TEXT NOT NULL,
    scope           TEXT NOT NULL,
    nonce           TEXT,

    -- PKCE
    pkce_challenge  TEXT,                       -- code_challenge (S256 hash)
    pkce_method     TEXT,                       -- always "S256" when present

    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,                -- NULL = still valid
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_codes_hash ON authorization_codes(code_hash);

-- ─────────────────────────────────────────────
-- Refresh tokens (rotation with family tracking)
-- ─────────────────────────────────────────────
CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE CASCADE, -- NULL for client_credentials

    -- All tokens issued from the same authorization form a family.
    -- If a revoked token in a family is replayed, the whole family is revoked.
    family_id       UUID NOT NULL,

    -- SHA-256 of the opaque token sent to the client
    token_hash      TEXT NOT NULL UNIQUE,

    scope           TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by     UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_hash      ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id, user_id);
