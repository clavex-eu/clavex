-- Add per-org synchronous claims-enrichment hook configuration.
-- When set, Clavex POSTs a JSON payload to this URL during token issuance
-- and merges the response claims into the access token (500 ms timeout, graceful fallback).
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS claims_enrichment_url    TEXT    DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS claims_enrichment_secret TEXT    DEFAULT NULL;
