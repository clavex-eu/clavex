-- 000149_credential_chaining.down.sql
DROP INDEX IF EXISTS idx_credential_configs_chain_source;
ALTER TABLE credential_configs
    DROP COLUMN IF EXISTS chain_source_vct,
    DROP COLUMN IF EXISTS chain_claims_mapping,
    DROP COLUMN IF EXISTS chain_offer_ttl_mins;
