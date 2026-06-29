-- RFC 9396 Rich Authorization Requests: store authorization_details JSON
-- alongside the authorization code so the token endpoint can embed it in
-- the issued access token.
ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS authorization_details JSONB;
