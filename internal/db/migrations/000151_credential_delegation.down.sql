-- 000151_credential_delegation.down.sql
ALTER TABLE credential_configs
    DROP COLUMN IF EXISTS delegated_by,
    DROP COLUMN IF EXISTS delegation_jwt;

DROP INDEX IF EXISTS idx_credential_configs_delegated;
