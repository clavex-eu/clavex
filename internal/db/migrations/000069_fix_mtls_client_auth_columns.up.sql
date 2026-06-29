-- 000069_fix_mtls_client_auth_columns: migration 000066 ran ALTER TABLE clients
-- instead of ALTER TABLE oidc_clients, so the mTLS columns were never added to
-- the actual table.  This migration adds them correctly.
ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS tls_client_auth_subject_dn TEXT,
    ADD COLUMN IF NOT EXISTS tls_client_auth_san_dns    TEXT;
