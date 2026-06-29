-- Revert to the migration 000132 per-scope active-key indexes (without key_use).
-- NOTE: this will fail if both an active 'sig' and an active 'enc' key exist in
-- the same scope; delete the enc keys first (see 000168 down migration).

DROP INDEX IF EXISTS signing_keys_one_active_global;
DROP INDEX IF EXISTS signing_keys_one_active_per_org;

CREATE UNIQUE INDEX signing_keys_one_active_global
    ON signing_keys (status)
    WHERE status = 'active' AND org_id IS NULL;

CREATE UNIQUE INDEX signing_keys_one_active_per_org
    ON signing_keys (org_id, status)
    WHERE status = 'active' AND org_id IS NOT NULL;
