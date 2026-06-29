ALTER TABLE action_executions
    DROP CONSTRAINT IF EXISTS action_executions_mode_check;

ALTER TABLE action_executions
    ADD CONSTRAINT action_executions_mode_check
        CHECK (mode IN ('fire_and_forget', 'mutation'));

ALTER TABLE action_executions
    DROP CONSTRAINT IF EXISTS action_executions_event_type_check;

ALTER TABLE action_executions
    ADD CONSTRAINT action_executions_event_type_check
        CHECK (event_type IN (
            'user.pre_login', 'user.pre_token',
            'user.created', 'user.updated', 'user.deleted',
            'user.pre_create', 'user.pre_update', 'user.pre_password_change'
        ));

ALTER TABLE action_targets
    DROP COLUMN IF EXISTS sandbox_code,
    DROP COLUMN IF EXISTS target_type;
