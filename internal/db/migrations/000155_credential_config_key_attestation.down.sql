-- 000155_credential_config_key_attestation.down.sql
ALTER TABLE credential_configs
    DROP COLUMN IF EXISTS require_key_attestation;
