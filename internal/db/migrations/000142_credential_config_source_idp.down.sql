DROP INDEX IF EXISTS idx_credential_configs_source_idp_type;
ALTER TABLE credential_configs DROP COLUMN IF EXISTS source_idp_type;
