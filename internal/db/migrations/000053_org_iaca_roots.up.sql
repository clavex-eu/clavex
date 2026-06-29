-- Per-org IACA (Issuer Authority CA) trust anchors for mdoc proximity verification.
-- Operators upload one or more X.509 root / intermediate CA certificates per org.
-- When TrustedRoots is populated, VerifyDeviceResponse enforces full chain validation
-- of the issuer certificate embedded in the mdoc IssuerAuth COSE_Sign1 header.

CREATE TABLE org_iaca_roots (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Human-readable label set by the operator (e.g. "IT PID Issuer Root CA").
    label               TEXT        NOT NULL,

    -- Derived from the certificate for fast lookup / deduplication.
    subject_dn          TEXT        NOT NULL,
    sha256_fingerprint  TEXT        NOT NULL,  -- hex-encoded SHA-256 of the raw DER cert

    -- PEM-encoded certificate (single cert, no chain).
    pem                 TEXT        NOT NULL,

    -- Optional: restrict this root to specific docTypes (e.g. '{"eu.europa.ec.eudi.pid.1"}').
    -- Empty array means "applies to all docTypes".
    doc_types           TEXT[]      NOT NULL DEFAULT '{}',

    -- Audit fields.
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID        REFERENCES users(id) ON DELETE SET NULL,
    is_active           BOOLEAN     NOT NULL DEFAULT true,

    -- Prevent duplicate uploads of the same cert within an org.
    UNIQUE (org_id, sha256_fingerprint)
);

CREATE INDEX idx_org_iaca_roots_org_active ON org_iaca_roots (org_id, is_active);
