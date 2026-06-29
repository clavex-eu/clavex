-- Migration 000086: passkey portability (FIDO Alliance CXF format)
-- Adds is_imported flag to distinguish ceremony-registered vs imported credentials.

ALTER TABLE mfa_credentials
    ADD COLUMN IF NOT EXISTS is_imported BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN mfa_credentials.is_imported IS
    'TRUE when the credential was imported via the CXF exchange format rather than '
    'registered through a live WebAuthn ceremony.';
