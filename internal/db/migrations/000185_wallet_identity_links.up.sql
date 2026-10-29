-- Wallet identities have issuer and tenant namespaces distinct from IdP links.
CREATE UNIQUE INDEX wallet_identity_user_org_idx ON identity.users(org_id,id);
CREATE TABLE identity.wallet_identity_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('dc+sd-jwt','mso_mdoc')),
    issuer TEXT NOT NULL,
    credential_type TEXT NOT NULL,
    claim_path TEXT[] NOT NULL CHECK (cardinality(claim_path) BETWEEN 1 AND 8),
    subject_digest BYTEA NOT NULL CHECK (octet_length(subject_digest)=32),
    verification_method TEXT NOT NULL CHECK (verification_method='administrative_review'),
    verified_by UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (org_id,user_id) REFERENCES identity.users(org_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX wallet_identity_active_subject_idx ON identity.wallet_identity_links
    (org_id,format,issuer,credential_type,claim_path,subject_digest) WHERE is_active;
CREATE INDEX wallet_identity_account_idx ON identity.wallet_identity_links(org_id,user_id);
