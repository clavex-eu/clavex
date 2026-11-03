ALTER TABLE identity.wallet_issuance_grants ADD COLUMN authorization_scope TEXT NOT NULL DEFAULT '';
ALTER TABLE identity.wallet_issuance_grants ADD COLUMN authorization_details JSONB NOT NULL DEFAULT '[]';
