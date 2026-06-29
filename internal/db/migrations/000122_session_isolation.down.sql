-- 000122_session_isolation.down.sql

ALTER TABLE oidc_clients
    DROP COLUMN IF EXISTS session_isolation;
