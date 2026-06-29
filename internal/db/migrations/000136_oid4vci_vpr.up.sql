-- 000136_oid4vci_vpr.up.sql
-- OID4VCI Verifiable Presentation Request (VPR) support.
--
-- Allows an issuer to require the wallet to present a Verifiable Presentation
-- before a credential is issued (e.g., identity-proofing during eIDAS 2.0
-- credential issuance). Based on OID4VCI §X / HAIP profile.

-- Per-credential-type VPR configuration.
ALTER TABLE credential_configs
    ADD COLUMN IF NOT EXISTS require_vp               BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS presentation_definition_vpr JSONB;

-- Track the in-flight VP session ID on the offer so the credential endpoint
-- can verify that the incoming vp_token closes the right session.
ALTER TABLE credential_offers
    ADD COLUMN IF NOT EXISTS vp_session_id TEXT;

CREATE INDEX IF NOT EXISTS credential_offers_vp_session
    ON credential_offers (vp_session_id)
    WHERE vp_session_id IS NOT NULL;
