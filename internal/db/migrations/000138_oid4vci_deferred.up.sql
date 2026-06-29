-- 000138_oid4vci_deferred.up.sql
-- OID4VCI Final §11: deferred credential issuance.
--
-- Adds:
--   credential_configs.deferred_issuance  — flag: issue synchronously or via deferred flow
--   deferred_credentials                  — pending issuance requests identified by transaction_id

ALTER TABLE credential_configs
    ADD COLUMN IF NOT EXISTS deferred_issuance BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS deferred_credentials (
    id                        UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id                    UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    transaction_id            TEXT        NOT NULL UNIQUE,
    -- offer that authorised the issuance (access-token binding)
    offer_id                  UUID        NOT NULL REFERENCES credential_offers(id) ON DELETE CASCADE,
    credential_configuration_id TEXT      NOT NULL,
    -- holder key from the proof JWT (DID or JWK thumbprint) — re-checked on completion
    proof_key_id              TEXT        NOT NULL DEFAULT '',
    -- pre-resolved claim payload (from offer.Payload + webhook merge, if any)
    claims_payload            JSONB,
    status                    TEXT        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending','completed','failed','expired')),
    -- populated when status = 'completed'
    credential_jwt            TEXT,
    -- populated when status = 'failed'
    error_code                TEXT,
    error_description         TEXT,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at                TIMESTAMPTZ NOT NULL,
    completed_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS deferred_credentials_org_status
    ON deferred_credentials (org_id, status, created_at DESC);
