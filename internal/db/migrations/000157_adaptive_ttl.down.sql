-- 000157_adaptive_ttl.down.sql
ALTER TABLE issued_credentials
    DROP COLUMN IF EXISTS adaptive_renewed_at,
    DROP COLUMN IF EXISTS presentation_count,
    DROP COLUMN IF EXISTS last_presented_at;

ALTER TABLE credential_configs
    DROP COLUMN IF EXISTS inactivity_revoke_days,
    DROP COLUMN IF EXISTS renewal_threshold,
    DROP COLUMN IF EXISTS max_ttl_seconds,
    DROP COLUMN IF EXISTS min_ttl_seconds,
    DROP COLUMN IF EXISTS adaptive_ttl;

DROP INDEX IF EXISTS idx_issued_adaptive_worker;
