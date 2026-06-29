CREATE TABLE webhooks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    url        TEXT        NOT NULL,
    events     TEXT[]      NOT NULL DEFAULT '{}',
    secret     TEXT        NOT NULL, -- used for HMAC-SHA256 signature
    is_active  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX webhooks_org_id_idx ON webhooks(org_id);
