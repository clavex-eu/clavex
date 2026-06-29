ALTER TABLE organizations
    DROP COLUMN IF EXISTS claims_enrichment_url,
    DROP COLUMN IF EXISTS claims_enrichment_secret;
