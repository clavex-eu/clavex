CREATE TABLE IF NOT EXISTS scim_push_configs (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name           TEXT        NOT NULL,
    endpoint_url   TEXT        NOT NULL,          -- SCIM 2.0 base URL (e.g. https://dir.example.com/scim/v2)
    bearer_token   TEXT        NOT NULL,          -- secret stored in plaintext (operator secures DB at rest)
    enabled_events TEXT[]      NOT NULL DEFAULT ARRAY['user.created','user.updated','user.deactivated']::TEXT[],
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scim_push_configs_org_id ON scim_push_configs (org_id);
