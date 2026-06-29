-- Migration 000143: per-org mdoc Document Signer (DS) key + certificate storage
--
-- In ISO 18013-5 / eIDAS 2.0 mdoc issuance, each issuer holds:
--   IACA (Issuer Authority CA) root certificate  ← already in org_iaca_roots
--   Document Signer (DS) certificate signed by the IACA
--   DS private key (ECDSA P-256 / P-384 / P-521)
--
-- When a wallet requests an mdoc credential via OID4VCI (format: "mso_mdoc"),
-- Clavex picks the active issuer for the requested docType and signs the MSO
-- with the DS private key.  The DS certificate is embedded in the IssuerAuth
-- COSE_Sign1 x5chain header so wallets can validate the certificate chain.
--
-- Key storage: DS private key is stored as PKCS#8 PEM (ECDSA).  In production
-- this should be replaced by a HSM/KMS reference; the PEM column is nullable
-- to support that migration path (set external_key_id instead).

CREATE TABLE org_mdoc_issuers (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id               UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    display_name         TEXT        NOT NULL,
    doc_type             TEXT        NOT NULL DEFAULT 'org.iso.18013.5.1.mDL',
    -- DS private key: PKCS#8 PEM (ECDSA P-256 recommended).
    -- Null when the key is managed externally (future KMS support).
    ds_private_key_pem   TEXT,
    -- DER-encoded DS certificate (PEM block stripped) signed by the IACA CA.
    ds_certificate_pem   TEXT        NOT NULL,
    -- Optional: IACA certificate PEM for full x5chain embedding.
    iaca_certificate_pem TEXT,
    -- How long each issued MSO is valid (default 30 days = 720 hours).
    validity_hours       INT         NOT NULL DEFAULT 720,
    is_active            BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, doc_type, is_active)
);

CREATE INDEX idx_org_mdoc_issuers_org_id ON org_mdoc_issuers (org_id);
