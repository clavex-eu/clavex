-- Old opaque tokens cannot be assigned a trustworthy issue time retroactively.
-- NULL expirations are therefore not accepted by the updated credential endpoint.
ALTER TABLE identity.credential_offers ADD COLUMN access_token_expires_at TIMESTAMPTZ;
