-- 000138_oid4vci_deferred.down.sql
DROP TABLE IF EXISTS deferred_credentials;

ALTER TABLE credential_configs
    DROP COLUMN IF EXISTS deferred_issuance;
