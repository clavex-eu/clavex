-- Login Flow Step Builder
-- Stores visual no-code authentication flow definitions.

-- A flow is an ordered sequence of steps applied during the login interaction.
-- One flow per org can be marked as the default (applied to all clients unless
-- a specific client assignment overrides it).
CREATE TABLE identity.login_flows (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT,
    is_default  BOOLEAN     NOT NULL DEFAULT FALSE,
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Only one default flow per org
CREATE UNIQUE INDEX login_flows_org_default_idx
    ON identity.login_flows(org_id) WHERE is_default = TRUE;

-- Each row is one step (block) in a flow, ordered by position ASC.
-- step_type controls which pre-built action runs; config is its JSON parameters.
--
-- Supported step_type values (no-code blocks):
--   check_attribute   — block/allow based on user profile field value
--   require_mfa       — force MFA step-up (block if not enrolled)
--   block_if_no_mfa   — deny login if user has no MFA enrolled
--   enrich_claims     — call an external HTTP API and map JSON fields to claims
--   set_claim         — set a claim to a static or user-attribute-derived value
--   webhook           — fire a POST to an external URL after login (non-blocking)
--   check_ip_risk     — deny or step-up based on IP risk score
--   require_email_verified — deny if user email is not verified
CREATE TABLE identity.login_flow_steps (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id     UUID        NOT NULL REFERENCES identity.login_flows(id) ON DELETE CASCADE,
    org_id      UUID        NOT NULL,
    step_type   TEXT        NOT NULL,
    position    INTEGER     NOT NULL DEFAULT 0,
    config      JSONB       NOT NULL DEFAULT '{}',
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX login_flow_steps_flow_idx ON identity.login_flow_steps(flow_id, position);

-- Explicit per-client flow override. When a client has an entry here its
-- logins use the assigned flow instead of the org default.
CREATE TABLE identity.login_flow_client_assignments (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id   UUID NOT NULL REFERENCES identity.login_flows(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    org_id    UUID NOT NULL,
    UNIQUE(client_id, org_id)
);

-- extra_claims carries claims produced by enrich_claims / set_claim steps
-- through the authorization code to the token exchange.
ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS extra_claims JSONB NOT NULL DEFAULT '{}';
