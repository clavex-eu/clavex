-- Per-org WebAuthn attestation enforcement policy.
-- When a row exists for an org, every passkey/WebAuthn credential
-- registered in that org is checked against these rules at enrollment time.
-- Credentials that violate the policy are rejected and never persisted.
CREATE TABLE IF NOT EXISTS webauthn_attestation_policies (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id               UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Master switch; when false the policy is skipped entirely.
    enabled              BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Reject credentials with attestation format "none" (no hardware proof).
    require_attestation  BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Optional allow-list of attestation statement formats.
    -- Empty array = any format accepted.
    -- Values: "packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "apple", "none"
    allowed_formats      TEXT[]      NOT NULL DEFAULT '{}',
    -- Optional allow-list of authenticator model AAGUIDs (lowercase UUID strings).
    -- Empty array = any AAGUID accepted.
    allowed_aaguids      TEXT[]      NOT NULL DEFAULT '{}',
    -- Optional allow-list of authenticator transports.
    -- Empty array = any transport accepted.
    -- Values: "internal", "usb", "nfc", "ble", "hybrid", "smart-card"
    allowed_transports   TEXT[]      NOT NULL DEFAULT '{}',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id)
);
