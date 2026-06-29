-- Access Review / Certification campaigns (Identity Governance)
-- Supports NIS2 / SOX periodic access certification workflows.

-- Campaign definition
CREATE TABLE IF NOT EXISTS identity.access_review_campaigns (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    description     TEXT,
    -- 'monthly' | 'quarterly' | 'annual' | 'one_time'
    frequency       TEXT        NOT NULL DEFAULT 'quarterly',
    -- 'pending' | 'active' | 'completed' | 'cancelled'
    status          TEXT        NOT NULL DEFAULT 'pending',
    -- When the review window opens
    starts_at       TIMESTAMPTZ NOT NULL,
    -- Hard deadline: auto-revoke unanswered items after this
    ends_at         TIMESTAMPTZ NOT NULL,
    -- Days before ends_at to send first/second reminder
    reminder_days   INTEGER[]   NOT NULL DEFAULT '{3,1}',
    -- If true, unanswered items are auto-revoked when ends_at is reached
    auto_revoke     BOOLEAN     NOT NULL DEFAULT TRUE,
    -- id of the user who created the campaign (nullable for system-created)
    created_by      UUID        REFERENCES identity.users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS access_review_campaigns_org_status_idx
    ON identity.access_review_campaigns (org_id, status);

-- Individual certification item: one user × one role, sent to a reviewer
CREATE TABLE IF NOT EXISTS identity.access_review_items (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id     UUID        NOT NULL REFERENCES identity.access_review_campaigns(id) ON DELETE CASCADE,
    org_id          UUID        NOT NULL,
    -- The user whose access is being certified
    user_id         UUID        NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    -- The role being certified
    role_id         UUID        NOT NULL REFERENCES identity.roles(id) ON DELETE CASCADE,
    -- The reviewer (typically the user's manager or a designated certifier)
    reviewer_id     UUID        NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    -- 'pending' | 'approved' | 'revoked' | 'auto_revoked'
    decision        TEXT        NOT NULL DEFAULT 'pending',
    -- One-time secure token embedded in approve/revoke email links
    token           TEXT        NOT NULL UNIQUE,
    -- When the reviewer submitted their decision
    decided_at      TIMESTAMPTZ,
    -- Optional justification comment
    comment         TEXT,
    -- When the last reminder email was sent
    last_reminded_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS access_review_items_campaign_idx
    ON identity.access_review_items (campaign_id, decision);

CREATE INDEX IF NOT EXISTS access_review_items_reviewer_idx
    ON identity.access_review_items (reviewer_id, decision);

CREATE INDEX IF NOT EXISTS access_review_items_token_idx
    ON identity.access_review_items (token);
