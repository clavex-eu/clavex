-- 000048_cross_org_trusts.up.sql
-- Cross-organisation token exchange trust relationships (RFC 8693).
--
-- A CrossOrgTrust record grants users from source_org the ability to exchange
-- their access/refresh tokens for a fresh token that is valid in target_org.
-- This enables multi-tenant architectures where a single Clavex installation
-- serves both a producer org (e.g. prod environment) and a consumer org
-- (e.g. staging, or a partner ISV with shared resources).
--
-- Trust is directional: A→B does not imply B→A.
--
-- Scope narrowing: if allowed_scopes IS NOT NULL the exchanged token's scope is
-- further intersected with this list (on top of the normal RFC 8693 narrowing).
-- Allowed client_ids: if allowed_client_ids IS NOT NULL only those clients may
-- perform the exchange on behalf of this trust relationship.

CREATE TABLE cross_org_trusts (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- NULL ⇒ any scope allowed; non-NULL ⇒ only these scopes can be requested
    allowed_scopes    TEXT[]      DEFAULT NULL,
    -- NULL ⇒ any client_id; non-NULL ⇒ only these client_ids may perform the exchange
    allowed_client_ids TEXT[]     DEFAULT NULL,
    is_active         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- free-form label: who/what created this trust (admin email, script name, …)
    created_by        TEXT        NOT NULL DEFAULT '',
    -- Prevent duplicate active trusts for the same pair
    CONSTRAINT uq_cross_org_trust_pair UNIQUE (source_org_id, target_org_id)
);

-- Fast lookup by source (list what an org trusts outbound)
CREATE INDEX idx_cross_org_trusts_source ON cross_org_trusts (source_org_id) WHERE is_active;
-- Fast lookup by target (list what orgs trust into this org)
CREATE INDEX idx_cross_org_trusts_target ON cross_org_trusts (target_org_id) WHERE is_active;
