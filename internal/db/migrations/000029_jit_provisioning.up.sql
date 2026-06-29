-- 000029: JIT provisioning controls on identity_providers

-- allow_jit: if false, logins via this IdP are blocked unless the user already exists.
-- roles_claim: the claim name to read group/role values from (e.g. "groups", "roles").
-- role_claim_mappings: JSONB mapping claim value → local role name,
--   e.g. '{"admins": "admin", "staff": "member"}'
ALTER TABLE identity_providers
    ADD COLUMN IF NOT EXISTS allow_jit          BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS roles_claim        TEXT,
    ADD COLUMN IF NOT EXISTS role_claim_mappings JSONB NOT NULL DEFAULT '{}';
