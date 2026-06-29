-- Rollback migration 000132

DROP INDEX IF EXISTS signing_keys_one_active_per_org;
DROP INDEX IF EXISTS signing_keys_one_active_global;
DROP INDEX IF EXISTS signing_keys_org_id;

-- Restore the original global constraint (may fail if multiple active keys
-- exist after adding per-org ones — manual cleanup would be required).
CREATE UNIQUE INDEX signing_keys_one_active
    ON signing_keys (status)
    WHERE status = 'active' AND org_id IS NULL;

ALTER TABLE signing_keys DROP COLUMN IF EXISTS org_id;
