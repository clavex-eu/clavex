-- Retain historical one-bit encodings; new lists explicitly select two bits.
ALTER TABLE identity.credential_status_lists ADD COLUMN bits INTEGER NOT NULL DEFAULT 1 CHECK (bits IN (1,2,4,8));
ALTER TABLE identity.issued_credentials ADD COLUMN is_suspended BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE identity.issued_credentials ADD COLUMN issuer_cose_hash TEXT;
ALTER TABLE identity.issued_credentials ADD CONSTRAINT issued_credential_state_check CHECK (NOT (is_revoked AND is_suspended));
CREATE UNIQUE INDEX issued_credential_issuer_cose_idx ON identity.issued_credentials(org_id,issuer_cose_hash) WHERE issuer_cose_hash IS NOT NULL;
