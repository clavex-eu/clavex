ALTER TABLE identity.org_password_policy
    ADD COLUMN IF NOT EXISTS breached_password_action TEXT NOT NULL DEFAULT 'off'
        CHECK (breached_password_action IN ('off', 'warn', 'block'));
