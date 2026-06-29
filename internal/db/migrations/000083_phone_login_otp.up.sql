-- First-factor phone login OTP codes.
-- Separate from phone_otp_codes (used for MFA / phone verification) so
-- the two purposes have independent TTLs, indexes, and cleanup.
CREATE TABLE IF NOT EXISTS phone_login_otps (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID        NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    phone            TEXT        NOT NULL,
    code_hash        TEXT        NOT NULL,
    login_session_id TEXT        NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    used_at          TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_phone_login_otps_org_phone
    ON phone_login_otps (org_id, phone);
