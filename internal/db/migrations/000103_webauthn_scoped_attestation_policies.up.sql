ALTER TABLE webauthn_attestation_policies ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid();

CREATE TABLE IF NOT EXISTS webauthn_scoped_attestation_policies (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scope_type  TEXT        NOT NULL CHECK (scope_type IN ('group', 'role')),
    scope_id    UUID        NOT NULL,
    policy      JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_wa_scoped_pol_org ON webauthn_scoped_attestation_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_wa_scoped_pol_scope ON webauthn_scoped_attestation_policies(scope_type, scope_id);
