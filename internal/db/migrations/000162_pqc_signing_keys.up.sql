-- Migration 000162: Post-Quantum Cryptography signing key support
-- (NIST FIPS 204 ML-DSA / Dilithium3, NIST FIPS 205 SLH-DSA / SPHINCS+)
--
-- Adds two nullable columns to signing_keys so PQC keys can coexist with the
-- classical RSA key in the same table:
--
--   Classical rows (algorithm=PS256):        pqc_algorithm IS NULL
--   ML-DSA-65 rows (algorithm=CV-ML-DSA-65): pqc_algorithm='ml-dsa-65'
--
-- key_enc stores the AES-256-GCM encrypted raw private key bytes for both
-- classical (PKCS#8 DER) and PQC (raw bytes from PrivateKey.Bytes()) rows.
-- pqc_public_key caches the raw public key bytes so JWKS can be built
-- without decrypting the private key on every request.

ALTER TABLE signing_keys
    ADD COLUMN IF NOT EXISTS pqc_algorithm  TEXT,   -- 'ml-dsa-65' | 'slh-dsa-sha2-128s' | NULL
    ADD COLUMN IF NOT EXISTS pqc_public_key BYTEA;  -- raw PQC public key bytes (JWKS cache)

-- Drop the old one-active-key index (which only allowed one active row total)
-- and replace it with a key-family-aware index that allows one active classical
-- key AND one active PQC key simultaneously (both globally and per org).
DROP INDEX IF EXISTS signing_keys_one_active;

CREATE UNIQUE INDEX signing_keys_one_active
    ON signing_keys (COALESCE(pqc_algorithm, ''), COALESCE(org_id::text, ''), status)
    WHERE status = 'active';
