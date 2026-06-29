-- Bind refresh tokens to the DPoP public key (JWK Thumbprint) that was used
-- at authorization time.  Enforced by ExchangeRefreshToken: if dpop_jkt is set,
-- the refresh request MUST include a DPoP proof with the matching public key.
-- RFC 9449 §6 and FAPI2 Security Profile ID2 §5 require this binding.
ALTER TABLE sessions.refresh_tokens
  ADD COLUMN IF NOT EXISTS dpop_jkt TEXT;
