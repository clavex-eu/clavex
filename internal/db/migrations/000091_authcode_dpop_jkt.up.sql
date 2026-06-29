ALTER TABLE authorization_codes
  ADD COLUMN IF NOT EXISTS dpop_jkt TEXT;
