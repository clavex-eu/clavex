-- 000154_credential_marketplace.down.sql
DROP TRIGGER  IF EXISTS trg_marketplace_tsv ON credential_marketplace_listings;
DROP FUNCTION IF EXISTS credential_marketplace_tsv_trigger();
DROP TABLE    IF EXISTS credential_marketplace_listings;
