-- Add pre-issuance webhook fields to credential_configs.
-- When pre_issuance_webhook_url is set, Clavex calls the URL synchronously
-- before emitting the SD-JWT-VC and gates issuance on the response.
ALTER TABLE credential_configs
  ADD COLUMN IF NOT EXISTS pre_issuance_webhook_url    TEXT,
  ADD COLUMN IF NOT EXISTS pre_issuance_webhook_secret TEXT;

COMMENT ON COLUMN credential_configs.pre_issuance_webhook_url IS
  'Optional HTTPS endpoint called before credential issuance. '
  'Body: {"event":"credential.pre_issuance","vct":...,"user_id":...,"org_id":...,"payload":{...}}. '
  'Expected response: {"allowed":bool,"claims":{...},"reason":"..."}';

COMMENT ON COLUMN credential_configs.pre_issuance_webhook_secret IS
  'HMAC-SHA256 signing secret for the X-Clavex-Signature header on pre-issuance calls.';
