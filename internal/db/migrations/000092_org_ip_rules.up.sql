CREATE TABLE IF NOT EXISTS org_ip_rules (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    type       text        NOT NULL CHECK (type IN ('allow', 'deny')),
    cidr       text        NOT NULL,
    notes      text        NOT NULL DEFAULT '',
    created_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_ip_rules_org_type ON org_ip_rules(org_id, type);
