-- Phone numbers per user
CREATE TABLE IF NOT EXISTS user_phone_numbers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE UNIQUE,
    phone       TEXT NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Short-lived phone OTP codes
CREATE TABLE IF NOT EXISTS phone_otp_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    -- 'mfa' | 'verify' | 'login'
    purpose     TEXT NOT NULL DEFAULT 'mfa',
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_phone_otp_user_id ON phone_otp_codes(user_id);

-- Per-org SMS provider settings
CREATE TABLE IF NOT EXISTS org_sms_settings (
    org_id      UUID PRIMARY KEY REFERENCES identity.organizations(id) ON DELETE CASCADE,
    -- 'stub' | 'twilio' | 'aws_sns' | 'vonage'
    provider    TEXT NOT NULL DEFAULT 'stub',
    config      JSONB NOT NULL DEFAULT '{}',
    is_active   BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable phone auth options on orgs
ALTER TABLE identity.organizations
    ADD COLUMN IF NOT EXISTS phone_mfa_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS sms_login_enabled  BOOLEAN NOT NULL DEFAULT FALSE;
