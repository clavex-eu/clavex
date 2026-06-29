DROP INDEX IF EXISTS idx_credential_configs_format;
ALTER TABLE credential_configs DROP COLUMN IF EXISTS credential_format;
