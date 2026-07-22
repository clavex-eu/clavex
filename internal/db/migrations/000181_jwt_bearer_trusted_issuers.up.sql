-- 000181_jwt_bearer_trusted_issuers.up.sql
-- Per-org trusted issuer configuration for the RFC 7523 JWT Bearer
-- authorization grant (grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer).
--
-- This is the generic RFC 7523 §2.1 authorization-grant profile: an org
-- registers an external issuer it trusts, and callers can then present a JWT
-- (assertion) signed by that issuer to obtain a Clavex access token for the
-- subject asserted by the JWT.
--
-- This is deliberately NOT the ID-JAG profile (draft-ietf-oauth-identity-
-- assertion-authz-grant) — see docs/ID-JAG-ROADMAP.md. No ID-JAG-specific
-- claims or semantics are encoded here; it is the stable building block that
-- an ID-JAG profile would be layered on top of once that draft stabilises.

CREATE TABLE jwt_bearer_trusted_issuers (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Must match the "iss" claim of presented assertions exactly.
    issuer         TEXT        NOT NULL,
    -- Inline JWKS used to verify assertion signatures. Takes precedence over
    -- jwks_uri when both are set (mirrors oidc_clients.jwks / jwks_uri).
    jwks           JSONB       DEFAULT NULL,
    jwks_uri       TEXT        DEFAULT NULL,
    -- Maps assertion claim names to Clavex access-token claim names, e.g.
    -- {"department": "org_dept"}. The "sub" claim always becomes the issued
    -- token's subject and is never remapped.
    claim_mappings JSONB       NOT NULL DEFAULT '{}',
    -- NULL ⇒ any scope allowed; non-NULL ⇒ only these scopes can be requested
    allowed_scopes TEXT[]      DEFAULT NULL,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by     TEXT        NOT NULL DEFAULT '',
    CONSTRAINT uq_jwt_bearer_trusted_issuer UNIQUE (org_id, issuer)
);

CREATE INDEX idx_jwt_bearer_trusted_issuers_org ON jwt_bearer_trusted_issuers (org_id) WHERE is_active;
