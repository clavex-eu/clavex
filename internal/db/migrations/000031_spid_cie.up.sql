-- ── SPID Service Provider config (one row per org) ───────────────────────────
CREATE TABLE spid_configs (
    org_id              UUID        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,

    -- SP identity (these go in the SP metadata and AuthnRequest Issuer)
    entity_id           TEXT        NOT NULL,

    -- Organization details (required by AgID in SP metadata)
    org_name            TEXT        NOT NULL,        -- e.g. "Acme S.r.l."
    org_display_name    TEXT        NOT NULL,
    org_url             TEXT        NOT NULL,

    -- Contact person (required in SP metadata)
    contact_email       TEXT        NOT NULL,
    contact_phone       TEXT,

    -- Legal identity (one of the two is required)
    vat_number          TEXT,                        -- Partita IVA  (private sector)
    ipa_code            TEXT,                        -- Codice IPA   (public sector / PA)
    entity_type         TEXT        NOT NULL DEFAULT 'private'
                            CHECK (entity_type IN ('private', 'public')),

    -- Authentication level requested (maps to SpidL1/L2/L3)
    authn_level         INT         NOT NULL DEFAULT 2 CHECK (authn_level BETWEEN 1 AND 3),

    -- Attribute set requested (see SPID technical rules)
    attribute_set       TEXT[]      NOT NULL DEFAULT ARRAY[
                            'spidCode','name','familyName','fiscalNumber'
                        ],

    -- Auto-generated per-org signing certificate (PEM)
    sp_cert_pem         TEXT,
    sp_key_pem          TEXT,       -- stored encrypted at-rest by the app layer

    is_active           BOOLEAN     NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Official SPID Identity Provider registry ──────────────────────────────────
-- One authoritative row per SPID IdP. Shared across all orgs.
-- Metadata XML is cached locally and refreshed periodically.
CREATE TABLE spid_idp_registry (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id           TEXT        NOT NULL UNIQUE,
    display_name        TEXT        NOT NULL,
    logo_url            TEXT,
    metadata_url        TEXT        NOT NULL,
    metadata_xml        TEXT,                   -- cached IdP metadata XML
    metadata_fetched_at TIMESTAMPTZ,
    is_active           BOOLEAN     NOT NULL DEFAULT true,
    is_test             BOOLEAN     NOT NULL DEFAULT false,  -- AgID validator IdP
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_spid_idp_active ON spid_idp_registry (is_active, is_test);

-- Seed the official SPID IdPs (metadata URLs from AgID registry 2024)
INSERT INTO spid_idp_registry (entity_id, display_name, logo_url, metadata_url, is_test) VALUES
('https://loginspid.aruba.it',
 'Aruba ID',
 'https://registry.spid.gov.it/api/download/idp/aruba/logo',
 'https://loginspid.aruba.it/metadata',
 false),

('https://identity.infocert.it',
 'InfoCert ID',
 'https://registry.spid.gov.it/api/download/idp/infocert/logo',
 'https://identity.infocert.it/metadata/metadata.xml',
 false),

('https://idp.namirialtsp.com/idp',
 'Namirial ID',
 'https://registry.spid.gov.it/api/download/idp/namirial/logo',
 'https://idp.namirialtsp.com/idp/metadata.xml',
 false),

('https://posteid.poste.it',
 'Poste ID',
 'https://registry.spid.gov.it/api/download/idp/poste/logo',
 'https://posteid.poste.it/jod-fs/metadata/metadata.xml',
 false),

('https://spid.register.it',
 'Register.it SPID',
 'https://registry.spid.gov.it/api/download/idp/register/logo',
 'https://spid.register.it/spidRegister/metadata.xml',
 false),

('https://identity.sieltecloud.it',
 'Sielte ID',
 'https://registry.spid.gov.it/api/download/idp/sielte/logo',
 'https://identity.sieltecloud.it/simplesaml/metadata.xml',
 false),

('https://login.id.tim.it/affwebservices/public/saml2sso',
 'TIM id',
 'https://registry.spid.gov.it/api/download/idp/tim/logo',
 'https://login.id.tim.it/affwebservices/public/saml2sso',
 false),

('https://spid.intesaid.com',
 'SPIDItalia (Intesa Sanpaolo)',
 'https://registry.spid.gov.it/api/download/idp/intesa/logo',
 'https://spid.intesaid.com/registry/metadata.xml',
 false),

('https://demo.spid.gov.it/idp',
 'SPID Test (AgID validator)',
 NULL,
 'https://demo.spid.gov.it/metadata',
 true);
