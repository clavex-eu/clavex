CREATE TABLE IF NOT EXISTS org_ip_allowlist (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    cidr       TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    created_by UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_ip_allowlist_org_id ON org_ip_allowlist(org_id);
