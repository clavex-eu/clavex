-- Migration 000168: request-object encryption key support
-- (OpenID Federation / RFC 9101 encrypted request objects, OpenID4VP JARM enc)
--
-- Adds a key_use discriminator to signing_keys so an encryption key (RSA-OAEP)
-- can coexist with the classical RSA signing key and the PQC key in the same
-- table:
--
--   Signing rows (token/ID-token/entity-statement signing): key_use = 'sig'
--   Encryption rows (request-object JWE decryption):         key_use = 'enc'
--
-- enc rows store an AES-256-GCM encrypted PKCS#8 DER RSA private key in key_enc,
-- exactly like sig rows; algorithm holds the JWE key-management alg
-- (e.g. 'RSA-OAEP-256'). The public half is published in the OP's JWKS with
-- use=enc so RPs can encrypt request objects to it.

ALTER TABLE signing_keys
    ADD COLUMN IF NOT EXISTS key_use TEXT NOT NULL DEFAULT 'sig'
        CHECK (key_use IN ('sig', 'enc'));

-- The active-key invariant must now be per key_use as well: one active sig key
-- AND one active enc key may coexist (both globally and per org, both classical
-- and PQC). Rebuild the partial unique index to include key_use.
DROP INDEX IF EXISTS signing_keys_one_active;

CREATE UNIQUE INDEX signing_keys_one_active
    ON signing_keys (key_use, COALESCE(pqc_algorithm, ''), COALESCE(org_id::text, ''), status)
    WHERE status = 'active';
