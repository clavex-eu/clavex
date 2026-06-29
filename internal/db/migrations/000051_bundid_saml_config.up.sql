-- ── BundID SAML Service Provider config (one row per org) ─────────────────────
-- BundID is the German federal digital identity portal operated by FITKO.
-- It acts as a SAML 2.0 Identity Proxy that aggregates:
--   • Online-Ausweis / nPA       (eIDAS High)
--   • ELSTER-Zertifikat           (eIDAS Substantial)
--   • Benutzername + Passwort     (eIDAS Low)
--
-- Production IdP metadata:   https://id.bund.de/idp/saml/metadata
-- Integration IdP metadata:  https://int.id.bund.de/idp/saml/metadata
--
-- SP registration: https://id.bund.de/de/fuer-dienstleister/registrierung
-- SP must submit: entity_id, ACS URL, SLO URL (optional), SP metadata XML.
-- FITKO reviews applications within 3-5 business days.
-- Integration environment is self-service (no review required).

CREATE TABLE bundid_saml_configs (
    org_id              UUID        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,

    -- SP identity (appears in the SP metadata <md:EntityDescriptor EntityID="...">)
    entity_id           TEXT        NOT NULL,

    -- Organization details (required by FITKO in SP metadata <md:Organization>)
    org_name            TEXT        NOT NULL,
    org_display_name    TEXT        NOT NULL,
    org_url             TEXT        NOT NULL,

    -- Technical contact (required in SP metadata <md:ContactPerson>)
    contact_email       TEXT        NOT NULL,
    contact_phone       TEXT,

    -- Environment: "production" or "integration"
    -- Determines which BundID IdP metadata URL to use.
    environment         TEXT        NOT NULL DEFAULT 'integration'
                            CHECK (environment IN ('production', 'integration')),

    -- Minimum required LoA (maps to SAML AuthnContextClassRef).
    -- Allowed values (see bundidsaml.LoA* constants):
    --   "low"         → username + password (Benutzername-Passwort)
    --   "substantial" → verified identity / ELSTER cert (eIDAS Substantial)
    --   "high"        → Online-Ausweis / nPA (eIDAS High)
    min_loa             TEXT        NOT NULL DEFAULT 'substantial'
                            CHECK (min_loa IN ('low', 'substantial', 'high')),

    -- Attributes requested in the SP metadata <md:RequestedAttribute>.
    -- Subset of bundidsaml.AllAttributes.
    attribute_set       TEXT[]      NOT NULL DEFAULT ARRAY[
                            'PersonIdentifier', 'CurrentFamilyName', 'CurrentGivenName'
                        ],

    -- Per-org SP signing / encryption certificate (PEM).
    -- Auto-generated on first save; cert must be sent to FITKO.
    sp_cert_pem         TEXT,
    sp_key_pem          TEXT,       -- stored encrypted at-rest by the app layer

    is_active           BOOLEAN     NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
