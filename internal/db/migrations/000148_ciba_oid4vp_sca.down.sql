DROP INDEX IF EXISTS idx_presentation_sessions_ciba_auth_req_id;

ALTER TABLE presentation_sessions
    DROP COLUMN IF EXISTS ciba_auth_req_id;

ALTER TABLE ciba_requests
    DROP COLUMN IF EXISTS vp_claims,
    DROP COLUMN IF EXISTS acr;
