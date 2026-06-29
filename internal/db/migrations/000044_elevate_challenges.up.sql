-- 000044_elevate_challenges.up.sql
-- Step-up MFA challenges (Elevate API).
--
-- Lifecycle: pending → completed | expired
-- The resource server creates a challenge, the user completes it on their
-- device, the resource server polls/receives an elevated short-lived JWT.

CREATE TABLE elevate_challenges (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Human-readable context for the challenge (shown to user during MFA prompt)
    reason          TEXT        NOT NULL DEFAULT '',
    -- Comma-separated list of MFA methods accepted: "totp", "webauthn"
    -- Empty = accept any method the user has enrolled
    allowed_methods TEXT[]      NOT NULL DEFAULT '{}',
    -- "pending" | "completed" | "expired"
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','completed','expired')),
    -- Short-lived elevated token issued on completion (RS256, acr=step-up, TTL=5min)
    elevated_token  TEXT,
    -- Caller identity for audit trail
    caller_ip       INET,
    caller_agent    TEXT,
    -- TTL: 10 minutes from creation
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_elevate_challenges_org_user
    ON elevate_challenges(org_id, user_id, created_at DESC);
CREATE INDEX idx_elevate_challenges_status
    ON elevate_challenges(status, expires_at)
    WHERE status = 'pending';
