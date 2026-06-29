-- Add selective_disclosure flag to credential_configs.
-- When TRUE (default) all mapped claims are placed in individual SD-JWT disclosures,
-- giving the holder per-claim selective disclosure (e.g. present only age_over_18
-- to a pharmacy without revealing given_name or fiscal_code).
-- When FALSE all claims are placed verbatim in the signed issuer JWT (no SD).
ALTER TABLE credential_configs
    ADD COLUMN IF NOT EXISTS selective_disclosure BOOLEAN NOT NULL DEFAULT TRUE;
