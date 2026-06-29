-- 000133_oid4vci_final_spec.down.sql
DROP INDEX IF EXISTS credential_offers_c_nonce;
ALTER TABLE credential_offers
    DROP COLUMN IF EXISTS c_nonce_expires_at,
    DROP COLUMN IF EXISTS c_nonce;
