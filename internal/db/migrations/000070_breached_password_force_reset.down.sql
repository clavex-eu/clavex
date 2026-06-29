ALTER TABLE identity.org_password_policy
    DROP CONSTRAINT IF EXISTS org_password_policy_breached_password_action_check;

ALTER TABLE identity.org_password_policy
    ADD CONSTRAINT org_password_policy_breached_password_action_check
        CHECK (breached_password_action IN ('off', 'warn', 'block'));
