-- Migration 000056: add acr column to sessions.authorization_codes
-- Stores the Authentication Context Class Reference value achieved during
-- login, so it can be included in the ID token acr claim (OIDC Core §2).
ALTER TABLE sessions.authorization_codes
    ADD COLUMN IF NOT EXISTS acr TEXT NOT NULL DEFAULT '';
