-- Client scopes: reusable, org-level scope definitions assignable to OIDC clients.
CREATE TABLE IF NOT EXISTS client_scopes (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT,
    protocol    TEXT        NOT NULL DEFAULT 'openid-connect',
    is_default  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

-- Many-to-many: which scopes are assigned to each client
CREATE TABLE IF NOT EXISTS client_scope_assignments (
    client_id   TEXT    NOT NULL REFERENCES oidc_clients(client_id) ON DELETE CASCADE,
    scope_id    UUID    NOT NULL REFERENCES client_scopes(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_client_scopes_org_id ON client_scopes(org_id);
CREATE INDEX IF NOT EXISTS idx_client_scope_assignments_client_id ON client_scope_assignments(client_id);
