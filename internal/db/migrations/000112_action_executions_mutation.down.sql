-- Revert constraint to original event types and drop mode column.
ALTER TABLE action_executions
    DROP CONSTRAINT IF EXISTS action_executions_event_type_check;

ALTER TABLE action_executions
    ADD CONSTRAINT action_executions_event_type_check
        CHECK (event_type IN (
            'user.pre_login', 'user.pre_token',
            'user.created', 'user.updated', 'user.deleted'
        ));

ALTER TABLE action_executions
    DROP COLUMN IF EXISTS mode;
