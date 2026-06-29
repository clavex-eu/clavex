DROP INDEX IF EXISTS signing_keys_one_active;

ALTER TABLE signing_keys
    DROP COLUMN IF EXISTS pqc_algorithm,
    DROP COLUMN IF EXISTS pqc_public_key;

-- Restore the original single-active-key constraint.
CREATE UNIQUE INDEX signing_keys_one_active
    ON signing_keys (status)
    WHERE status = 'active';
