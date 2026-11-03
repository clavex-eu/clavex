DROP INDEX identity.deferred_credential_one_per_offer_idx;
ALTER TABLE identity.deferred_credentials DROP COLUMN delivered_at;
DROP TABLE identity.wallet_issuance_tokens;
DROP TABLE identity.wallet_issuance_grants;
-- Downgrading cannot restore revoked new grants as legacy bearer grants.
UPDATE identity.credential_offers SET access_token_hash=NULL,access_token_expires_at=NULL WHERE wallet_grant_version=1;
ALTER TABLE identity.credential_offers DROP COLUMN wallet_grant_version;
DROP INDEX identity.credential_offer_org_id_idx;
