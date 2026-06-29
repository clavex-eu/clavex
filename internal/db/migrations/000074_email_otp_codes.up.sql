-- Email OTP codes for passwordless login (6-digit code sent via email).
-- Similar to phone_otp_codes but tied to email instead of user_id,
-- so it also works for user provisioning (JIT) flows.
CREATE TABLE IF NOT EXISTS email_otp_codes (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    -- email is the primary identifier; user_id is set only when the user already exists
    email            TEXT NOT NULL,
    user_id          UUID REFERENCES identity.users(id) ON DELETE CASCADE,
    code_hash        TEXT NOT NULL,
    -- 'login' = passwordless first factor
    purpose          TEXT NOT NULL DEFAULT 'login',
    -- login_session_id ties the OTP to the in-progress OIDC session (Redis key)
    login_session_id TEXT NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    used_at          TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_otp_org_email ON email_otp_codes(org_id, email);
CREATE INDEX IF NOT EXISTS idx_email_otp_expires   ON email_otp_codes(expires_at);
