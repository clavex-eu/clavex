-- Down migration 000171: drop BYO certificate support from custom domains.

ALTER TABLE org_custom_domains
    DROP COLUMN IF EXISTS cert_source,
    DROP COLUMN IF EXISTS cert_pem,
    DROP COLUMN IF EXISTS cert_key_enc;
