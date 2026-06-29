-- 000156_revocation_network.up.sql
-- Cross-installation Revocation Network: when a credential is revoked on this
-- installation the event is propagated via SSF CAEP credential-change SETs to
-- every active federated partner so that documents stolen or lost are revoked
-- everywhere simultaneously.
--
-- Trust model: each partner pair exchanges two shared tokens out-of-band:
--   inbound_token  — the hashed secret that PARTNERS include in Bearer when
--                    posting SETs to US (we look up the row by this hash).
--   outbound_token — the plaintext secret WE include in Bearer when posting
--                    SETs to the PARTNER's ssf_endpoint.
-- The partner's public keys are fetched on demand from their jwks_uri and
-- cached in-memory; they are used to verify the SET signature on inbound events.

CREATE TABLE IF NOT EXISTS federated_installations (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- entity_id is the partner's canonical base URL / OpenID entity identifier.
    entity_id        TEXT        NOT NULL,
    display_name     TEXT        NOT NULL DEFAULT '',
    -- jwks_uri is the partner's JWKS endpoint used to verify inbound SET signatures.
    jwks_uri         TEXT        NOT NULL,
    -- inbound_token_hash is SHA-256 of the secret the partner includes in
    -- "Authorization: Bearer <token>" when it sends SETs to us.
    inbound_token_hash TEXT      NOT NULL,
    -- outbound_token is the secret we include in Bearer when sending SETs
    -- to the partner's ssf_endpoint.  Stored plaintext (rotatable).
    outbound_token   TEXT        NOT NULL,
    -- ssf_endpoint is the partner's inbound revocation URL.
    ssf_endpoint     TEXT        NOT NULL,
    -- propagate_on lists the revocation reasons that trigger cross-installation
    -- propagation.  Default: stolen documents and key compromise.
    propagate_on     TEXT[]      NOT NULL DEFAULT ARRAY['stolen','document_loss','compromised','security_incident'],
    is_active        BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_federated_installations_org
    ON federated_installations (org_id) WHERE is_active;
