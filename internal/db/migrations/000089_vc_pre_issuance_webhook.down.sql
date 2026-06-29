ALTER TABLE credential_configs
  DROP COLUMN IF EXISTS pre_issuance_webhook_url,
  DROP COLUMN IF EXISTS pre_issuance_webhook_secret;
