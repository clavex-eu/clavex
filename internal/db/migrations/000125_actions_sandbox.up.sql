-- Actions V2 — sandbox mode (inline JS execution).
--
-- Adds sandbox mode to action_targets and action_executions:
--
--   target_type  TEXT — 'http' (existing) | 'sandbox' (new: code runs in-process)
--   sandbox_code TEXT — the JS source to execute (populated when target_type='sandbox')
--
-- When target_type='sandbox':
--   - `url` may be empty / ignored
--   - `sandbox_code` contains the JavaScript source
--   - the function `onEvent(event)` is called with the event payload
--   - return value is the action response (same shape as HTTP response)
--
-- Extends event_type to include 'user.pre_register' (pre-signup hook).

ALTER TABLE action_targets
    ADD COLUMN IF NOT EXISTS target_type  TEXT NOT NULL DEFAULT 'http'
        CHECK (target_type IN ('http', 'sandbox')),
    ADD COLUMN IF NOT EXISTS sandbox_code TEXT;

-- URL is no longer required for sandbox targets (enforced at application level).

-- Extend allowed event types with pre-register.
ALTER TABLE action_executions
    DROP CONSTRAINT IF EXISTS action_executions_event_type_check;

ALTER TABLE action_executions
    ADD CONSTRAINT action_executions_event_type_check
        CHECK (event_type IN (
            'user.pre_login',          -- sync: can deny login or inject claims
            'user.pre_token',          -- sync: can inject / override token claims
            'user.created',            -- async: external provisioning
            'user.updated',            -- async: sync attributes
            'user.deleted',            -- async: deprovisioning
            'user.pre_create',         -- mutation: can modify or deny new-user request
            'user.pre_update',         -- mutation: can modify or deny user-update request
            'user.pre_password_change',-- mutation: can deny password change
            'user.pre_register'        -- sync/sandbox: pre-signup hook (can deny or enrich)
        ));

-- Also extend mode to include 'sandbox'.
ALTER TABLE action_executions
    DROP CONSTRAINT IF EXISTS action_executions_mode_check;

ALTER TABLE action_executions
    ADD CONSTRAINT action_executions_mode_check
        CHECK (mode IN ('fire_and_forget', 'mutation', 'sandbox'));
