-- Per-organization SAML IdP signing certificates.
-- Allows each tenant to have its own signing key/cert pair, or share the global one.
CREATE TABLE idp_certificates (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cert_pem     TEXT        NOT NULL,  -- X.509 certificate, PEM-encoded
    key_pem      TEXT        NOT NULL,  -- RSA private key, PEM-encoded (PKCS#8)
    is_active    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    UNIQUE(org_id, is_active) -- only one active cert per org at a time
);

-- Add signing_cert_fingerprint to saml_service_providers so we know which IdP
-- cert the SP trusts (helps with cert rotation).
ALTER TABLE saml_service_providers
    ADD COLUMN IF NOT EXISTS idp_cert_id UUID REFERENCES idp_certificates(id) ON DELETE SET NULL;
