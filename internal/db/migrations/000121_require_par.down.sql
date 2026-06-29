-- 000121_require_par.down.sql

ALTER TABLE oidc_clients
    DROP COLUMN IF EXISTS require_par;
