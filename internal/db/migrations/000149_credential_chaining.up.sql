-- 000149_credential_chaining.up.sql
-- Credential Chaining: automatic credential issuance triggered by a verifiable
-- presentation. When a wallet presents a credential of type chain_source_vct,
-- Clavex automatically creates a pre-authorized offer for this credential config
-- and returns the openid-credential-offer:// deep-link in the OID4VP response.
--
-- Use case: present CIE digital (ISO 18013-5 mDL mdoc or SD-JWT-VC) →
--   automatically receive a residence certificate — zero extra authentication,
--   maximum assurance. The input credential becomes the auth mechanism.

ALTER TABLE credential_configs
    -- VCT (or ISO 18013-5 doctype) of the input credential that triggers issuance
    -- of this credential. When non-null the credential is a "chained" type.
    ADD COLUMN IF NOT EXISTS chain_source_vct      TEXT,
    -- JSON map {"output_claim": "input_vp_claim"} for claim transformation.
    -- When null all input VP claims are forwarded verbatim (minus system claims).
    ADD COLUMN IF NOT EXISTS chain_claims_mapping   JSONB,
    -- Lifetime (minutes) of the auto-generated pre-authorized code offer.
    ADD COLUMN IF NOT EXISTS chain_offer_ttl_mins  INT NOT NULL DEFAULT 15;

CREATE INDEX IF NOT EXISTS idx_credential_configs_chain_source
    ON credential_configs(org_id, chain_source_vct)
    WHERE chain_source_vct IS NOT NULL AND is_active = TRUE;
