-- Actions V2 — mutation mode extension.
--
-- Adds a `mode` column to action_executions to distinguish between:
--   fire_and_forget — current behavior: POST to target asynchronously, ignore response
--   mutation        — synchronous: POST request payload to target, use modified
--                     response body as the actual data to process (request mutation).
--
-- Also extends the event_type constraint to include new pre-* mutation events:
--   user.pre_create          — before creating a new user (can modify or deny)
--   user.pre_update          — before updating a user (can modify or deny)
--   user.pre_password_change — before changing a password (can deny)

ALTER TABLE action_executions
    ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'fire_and_forget'
        CHECK (mode IN ('fire_and_forget', 'mutation'));

-- Extend allowed event types.
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
            'user.pre_password_change' -- mutation: can deny password change
        ));
