-- 000029 rollback
ALTER TABLE identity_providers
    DROP COLUMN IF EXISTS allow_jit,
    DROP COLUMN IF EXISTS roles_claim,
    DROP COLUMN IF EXISTS role_claim_mappings;
