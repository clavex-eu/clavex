ALTER TABLE identity.wallet_issuance_grants ADD COLUMN client_auth_method TEXT NOT NULL DEFAULT 'none';
ALTER TABLE identity.wallet_issuance_grants ADD COLUMN attestation_jkt TEXT NOT NULL DEFAULT '';
ALTER TABLE identity.wallet_issuance_grants ADD COLUMN status_parents JSONB NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(status_parents)='array');
ALTER TABLE identity.wallet_issuance_grants ADD COLUMN authorization_code_id UUID;
CREATE UNIQUE INDEX wallet_grant_authorization_code_idx ON identity.wallet_issuance_grants(authorization_code_id) WHERE authorization_code_id IS NOT NULL;
