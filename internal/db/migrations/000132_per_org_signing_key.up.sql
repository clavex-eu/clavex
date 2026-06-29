-- Migration 000132: per-org signing keys (BYOK)
--
-- Adds org_id to signing_keys so each organisation can have its own RSA
-- signing key.  NULL org_id = global installation key (backward compat).
-- NOT NULL org_id = key owned by that organisation (BYOK / enterprise).
--
-- The existing partial unique index (one active key globally) is replaced by
-- two narrower indexes:
--   • one active key for the global scope   (org_id IS NULL)
--   • one active key per organisation       (org_id IS NOT NULL)

ALTER TABLE signing_keys
    ADD COLUMN org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Drop the old global-only constraint before creating the replacements.
DROP INDEX IF EXISTS signing_keys_one_active;

CREATE UNIQUE INDEX signing_keys_one_active_global
    ON signing_keys (status)
    WHERE status = 'active' AND org_id IS NULL;

CREATE UNIQUE INDEX signing_keys_one_active_per_org
    ON signing_keys (org_id, status)
    WHERE status = 'active' AND org_id IS NOT NULL;

-- Speed up per-org look-ups.
CREATE INDEX signing_keys_org_id ON signing_keys (org_id) WHERE org_id IS NOT NULL;
