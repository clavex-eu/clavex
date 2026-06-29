-- 000036: per-org auth-flow policy rules
-- Enables operators to configure "require MFA from external IPs",
-- "deny logins from blocked countries" etc. without code changes.

CREATE TABLE IF NOT EXISTS org_auth_policies (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Human-readable name for the policy rule.
    name        TEXT        NOT NULL,
    -- Evaluation order; lower = evaluated first.
    priority    INT         NOT NULL DEFAULT 100,
    -- Whether this rule is active.
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Action to take when all conditions match.
    -- One of: allow | deny | require_mfa | step_up
    action      TEXT        NOT NULL CHECK (action IN ('allow','deny','require_mfa','step_up')),
    -- Conditions as JSONB (see internal/policy/engine.go for schema).
    conditions  JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_org_auth_policies_org ON org_auth_policies(org_id, priority ASC);
