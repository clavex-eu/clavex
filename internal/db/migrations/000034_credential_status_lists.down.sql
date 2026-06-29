-- Rollback 000034

ALTER TABLE issued_credentials
    DROP COLUMN IF EXISTS is_revoked,
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS revocation_reason,
    DROP COLUMN IF EXISTS status_list_id,
    DROP COLUMN IF EXISTS status_index;

DROP INDEX IF EXISTS idx_issued_credentials_status_list;
DROP TABLE IF EXISTS credential_status_lists;
