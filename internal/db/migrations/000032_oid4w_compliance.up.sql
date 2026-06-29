-- 000032_oid4w_compliance.up.sql
-- OpenID for Verifiable Credentials (OID4VCI / OID4VP) and GDPR compliance tables.

-- ── OID4VCI: credential type configurations ───────────────────────────────────
CREATE TABLE credential_configs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- vct is the Verifiable Credential Type URI (SD-JWT-VC "vct" claim)
    vct             TEXT        NOT NULL,
    display_name    TEXT        NOT NULL,
    description     TEXT,
    -- claims_mapping: { "given_name": "first_name", "family_name": "last_name", ... }
    -- keys are SD-JWT claim names, values are Clavex user attribute names
    claims_mapping  JSONB       NOT NULL DEFAULT '{}',
    ttl_seconds     INT         NOT NULL DEFAULT 86400,
    is_active       BOOL        NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, vct)
);

CREATE INDEX idx_credential_configs_org_id ON credential_configs(org_id);

-- ── OID4VCI: pre-authorized code offers ──────────────────────────────────────
CREATE TABLE credential_offers (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id               UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id              UUID        REFERENCES users(id) ON DELETE SET NULL,
    vct                  TEXT        NOT NULL,
    pre_auth_code        TEXT        NOT NULL UNIQUE,
    -- Optional TX code (user_pin) stored as SHA-256 hex
    tx_code_hash         TEXT,
    -- Set after successful token exchange
    access_token_hash    TEXT        UNIQUE,
    status               TEXT        NOT NULL DEFAULT 'pending'
                                     CHECK (status IN ('pending', 'used', 'expired')),
    expires_at           TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credential_offers_org_id     ON credential_offers(org_id);
CREATE INDEX idx_credential_offers_pre_auth   ON credential_offers(pre_auth_code);
CREATE INDEX idx_credential_offers_token_hash ON credential_offers(access_token_hash)
    WHERE access_token_hash IS NOT NULL;

-- ── OID4VCI: issued credential audit trail ────────────────────────────────────
CREATE TABLE issued_credentials (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID        REFERENCES users(id) ON DELETE SET NULL,
    vct             TEXT        NOT NULL,
    -- SHA-256 hex of the full SD-JWT string (for audit/revocation)
    sd_jwt_hash     TEXT        NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);

CREATE INDEX idx_issued_credentials_org_id  ON issued_credentials(org_id);
CREATE INDEX idx_issued_credentials_user_id ON issued_credentials(user_id)
    WHERE user_id IS NOT NULL;

-- ── OID4VP: presentation request sessions ─────────────────────────────────────
CREATE TABLE presentation_sessions (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Short opaque ID used in request_uri: /:org_slug/wallet/request/:request_id
    request_id              TEXT        NOT NULL UNIQUE,
    presentation_definition JSONB       NOT NULL,
    -- Where the wallet POSTs the vp_token
    response_uri            TEXT        NOT NULL,
    -- Optional: redirect the browser after verification
    redirect_uri            TEXT,
    state                   TEXT,
    nonce                   TEXT        NOT NULL,
    status                  TEXT        NOT NULL DEFAULT 'pending'
                                        CHECK (status IN ('pending', 'verified', 'failed', 'expired')),
    -- Populated on successful verification
    vp_claims               JSONB,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_presentation_sessions_org_id     ON presentation_sessions(org_id);
CREATE INDEX idx_presentation_sessions_request_id ON presentation_sessions(request_id);

-- ── GDPR Article 30: Records of Processing Activities ─────────────────────────
CREATE TABLE gdpr_processing_records (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    activity_name    TEXT        NOT NULL,
    purpose          TEXT        NOT NULL,
    -- e.g. "legitimate_interest" | "contract" | "legal_obligation" | "consent"
    legal_basis      TEXT        NOT NULL,
    -- JSON array of strings: ["email_address", "ip_address", ...]
    data_categories  JSONB       NOT NULL DEFAULT '[]',
    -- e.g. "employees", "customers", "website_visitors"
    data_subjects    TEXT        NOT NULL,
    -- e.g. "until account deletion + 90 days"
    retention_period TEXT        NOT NULL,
    -- JSON array of objects: [{"name": "...", "country": "..."}]
    recipients       JSONB       NOT NULL DEFAULT '[]',
    -- JSON array of processor objects (Article 28 processors)
    processors       JSONB       NOT NULL DEFAULT '[]',
    is_active        BOOL        NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gdpr_processing_records_org_id ON gdpr_processing_records(org_id);
