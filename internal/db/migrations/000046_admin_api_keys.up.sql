CREATE TABLE admin_api_keys (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    key_hash     TEXT        NOT NULL UNIQUE,   -- SHA-256 hex of the raw key
    key_prefix   TEXT        NOT NULL,          -- first 8 chars after "clv_" for display
    scope        TEXT        NOT NULL DEFAULT 'read-write'
                             CHECK (scope IN ('read-only', 'read-write', 'provision-only')),
    created_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    is_active    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast lookup by hash on active keys only.
CREATE UNIQUE INDEX idx_admin_api_keys_active_hash
    ON admin_api_keys (key_hash)
    WHERE is_active = TRUE;
