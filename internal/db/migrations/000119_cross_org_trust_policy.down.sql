-- 000119_cross_org_trust_policy.down.sql
ALTER TABLE cross_org_trusts
    DROP COLUMN IF EXISTS max_token_ttl,
    DROP COLUMN IF EXISTS require_mfa;
