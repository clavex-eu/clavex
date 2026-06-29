-- Down migration 000168: drop request-object encryption key support.

-- Remove any encryption rows before dropping the discriminator column.
DELETE FROM signing_keys WHERE key_use = 'enc';

DROP INDEX IF EXISTS signing_keys_one_active;

ALTER TABLE signing_keys
    DROP COLUMN IF EXISTS key_use;

-- Restore the migration 000162 index (key-family-aware, without key_use).
CREATE UNIQUE INDEX signing_keys_one_active
    ON signing_keys (COALESCE(pqc_algorithm, ''), COALESCE(org_id::text, ''), status)
    WHERE status = 'active';
