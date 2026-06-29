-- Migration 000127: signing_keys table
-- Stores RSA signing keys encrypted at rest with AES-256-GCM (KEK from
-- CLAVEX_AUTH_KEY_ENCRYPTION_KEY).  Replaces the single PEM file approach so
-- Rotate() survives container restarts and horizontal scaling.
--
-- Wire format stored in key_enc (BYTEA):
--   nonce(12 bytes) || AES-256-GCM-ciphertext+tag of PKCS#8 DER
--
-- The partial unique index signing_keys_one_active enforces the invariant that
-- at most one key is active at any time.

CREATE TABLE signing_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kid         TEXT        NOT NULL UNIQUE,
    algorithm   TEXT        NOT NULL DEFAULT 'PS256',
    -- AES-256-GCM encrypted PKCS#8 DER: nonce(12) || ciphertext+tag
    key_enc     BYTEA       NOT NULL,
    -- 'active'  — currently used for new token signing
    -- 'retired' — still served in JWKS for token verification (grace period)
    -- 'expired' — removed from JWKS; kept for audit trail only
    status      TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'retired', 'expired')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Set when the key is retired via Rotate().
    retired_at  TIMESTAMPTZ,
    -- Retired keys stop being served in JWKS after expires_at (retired_at + 24 h).
    -- NULL for active / expired keys.
    expires_at  TIMESTAMPTZ
);

-- Enforce: only one active key at a time.
CREATE UNIQUE INDEX signing_keys_one_active
    ON signing_keys (status)
    WHERE status = 'active';
