-- TOTP backup codes: 10 one-time recovery codes per user, SHA-256 hashed.
-- Generated at TOTP enrollment confirmation; shown exactly once in plain text.
-- Each code is consumed (deleted) on first use.
CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    code_hash  TEXT        NOT NULL,           -- SHA-256(plain_code) hex
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS totp_backup_codes_user_id_idx ON totp_backup_codes (user_id);
