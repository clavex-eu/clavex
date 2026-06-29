DROP TABLE IF EXISTS identity.login_flow_client_assignments;
DROP TABLE IF EXISTS identity.login_flow_steps;
DROP TABLE IF EXISTS identity.login_flows;
ALTER TABLE authorization_codes DROP COLUMN IF EXISTS extra_claims;
