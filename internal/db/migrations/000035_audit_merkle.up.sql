-- 000035: Merkle tree checkpoints for audit log immutability
-- Provides cryptographic proof-of-immutability for NIS2 / enterprise auditors.
--
-- Every MERKLE_CHECKPOINT_INTERVAL audit_log rows per org, a background job
-- (or on-demand via API) computes the SHA-256 Merkle root of the batch and
-- signs it with the server's RSA key.  The chain of checkpoints can be
-- verified offline without access to the database.

CREATE TABLE audit_merkle_checkpoints (
    id              BIGSERIAL   PRIMARY KEY,
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Inclusive range of audit_log row IDs covered by this checkpoint.
    first_log_id    BIGINT      NOT NULL,
    last_log_id     BIGINT      NOT NULL,
    log_count       INT         NOT NULL,
    -- SHA-256 Merkle root of the batch (hex-encoded).
    merkle_root     TEXT        NOT NULL,
    -- SHA-256 hash of the previous checkpoint's merkle_root (empty string for the first).
    prev_root       TEXT        NOT NULL DEFAULT '',
    -- Hash chain: SHA-256(prev_root || merkle_root) for tamper detection.
    chain_hash      TEXT        NOT NULL,
    -- RS256 signature over chain_hash, base64url-encoded.
    signature       TEXT        NOT NULL,
    -- Key ID of the signing key used (matches JWKS kid).
    kid             TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-org lookup: find all checkpoints in order.
CREATE INDEX idx_merkle_checkpoints_org ON audit_merkle_checkpoints(org_id, id ASC);
-- Verify a specific log range efficiently.
CREATE INDEX idx_merkle_checkpoints_range ON audit_merkle_checkpoints(org_id, first_log_id, last_log_id);
