-- Org-level allowed audiences for AI agent tokens (internal/handler/agent_token.go).
--
-- Agent tokens are org+user scoped (no oidc_clients row), so they cannot
-- reuse oidc_clients.allowed_audiences (migration 000163, RFC 8693 token
-- exchange). This is the analogous allowlist for the agent-token "aud"
-- claim: cloud providers (AWS STS AssumeRoleWithWebIdentity, Azure AD
-- federated credentials, GCP Workload Identity Federation) validate the
-- standard OIDC `aud` claim strictly against a pre-registered value
-- (e.g. "sts.amazonaws.com", "api://AzureADTokenExchange", or a GCP pool
-- provider audience) — Clavex never calls those STS/WIF endpoints itself;
-- the requesting Terraform provider (aws/azurerm/google) does its own
-- exchange using the agent token as the input id_token.
--
-- Empty array (default) preserves today's behaviour: the agent token's
-- audience is always the issuer itself, and no external audience may be
-- requested.
ALTER TABLE organizations
    ADD COLUMN agent_token_allowed_audiences TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN organizations.agent_token_allowed_audiences IS
    'Allowed "aud" values agent-token issuance may request beyond the issuer itself (e.g. cloud STS/WIF audiences for Terraform federation). Empty = agent tokens are only audienced to the issuer.';

-- Persist the resolved audience on each issued agent token for audit/list
-- purposes (nullable: NULL means "issuer default", matching legacy tokens
-- issued before this migration).
ALTER TABLE agent_tokens
    ADD COLUMN audience TEXT;

COMMENT ON COLUMN agent_tokens.audience IS
    'The "aud" claim embedded in the signed JWT at issuance time. NULL = issuer default (legacy behaviour).';
