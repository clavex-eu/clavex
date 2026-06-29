-- 000133_oid4vci_final_spec.up.sql
-- OID4VCI Final spec (September 2025) alignment.
--
-- Adds c_nonce storage to credential_offers so the issuer can validate
-- the proof JWT nonce sent by the wallet in the Credential Request.
-- Required by OID4VCI Final §8 (proof validation).

ALTER TABLE credential_offers
    ADD COLUMN IF NOT EXISTS c_nonce TEXT,
    ADD COLUMN IF NOT EXISTS c_nonce_expires_at TIMESTAMPTZ;

-- Index for fast c_nonce lookup during credential endpoint validation.
CREATE INDEX IF NOT EXISTS credential_offers_c_nonce
    ON credential_offers (c_nonce)
    WHERE c_nonce IS NOT NULL;
