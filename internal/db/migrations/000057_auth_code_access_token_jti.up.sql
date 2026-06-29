ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS access_token_jti TEXT;
