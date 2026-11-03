-- Independent pre-authorized wallet grants; existing tokens receive no invented refresh rights.
CREATE UNIQUE INDEX credential_offer_org_id_idx ON identity.credential_offers(org_id,id);
-- Persist the generation marker even if a user deletion cascades the grant.
-- An invalidated new token must never fall back to the legacy offer hash.
ALTER TABLE identity.credential_offers ADD COLUMN wallet_grant_version SMALLINT NOT NULL DEFAULT 0 CHECK(wallet_grant_version IN (0,1));
CREATE TABLE identity.wallet_issuance_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    offer_id UUID NOT NULL UNIQUE,
    user_id UUID,
    configuration_id UUID NOT NULL,
    vct TEXT NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    dpop_jkt TEXT NOT NULL DEFAULT '',
    mtls_x5t_s256 TEXT NOT NULL DEFAULT '',
    deferred_allowed BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    FOREIGN KEY(org_id,offer_id) REFERENCES identity.credential_offers(org_id,id) ON DELETE CASCADE,
    FOREIGN KEY(org_id,user_id) REFERENCES identity.users(org_id,id) ON DELETE CASCADE
);
CREATE TABLE identity.wallet_issuance_tokens (
    token_hash TEXT PRIMARY KEY,
    grant_id UUID NOT NULL REFERENCES identity.wallet_issuance_grants(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('access','refresh')),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX wallet_issuance_tokens_grant_idx ON identity.wallet_issuance_tokens(grant_id);
ALTER TABLE identity.deferred_credentials ADD COLUMN delivered_at TIMESTAMPTZ;
CREATE UNIQUE INDEX deferred_credential_one_per_offer_idx ON identity.deferred_credentials(offer_id);
