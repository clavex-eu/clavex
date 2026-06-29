-- 000152_user_identity_import.up.sql
-- Identity Continuity: verified identity portability between Clavex installations.
--
-- An end-user with an account on "Clavex A" (e.g. a university) can register on
-- "Clavex B" (e.g. a municipality) and import their already-verified identity by
-- presenting an SD-JWT-VC issued by A.  B verifies the credential against A's
-- OpenID Federation trust chain, extracts identity claims, and pre-populates the
-- user profile — no re-identification required.
--
-- This is NOT SSO: the user creates a distinct account on B.  The feature provides
-- portability of verified profile data (given_name, family_name, date_of_birth …)
-- between independent Clavex deployments without requiring the user to re-submit
-- original documents.

ALTER TABLE users
    -- Base URL of the Clavex installation that issued the imported credential.
    -- Non-null when the user's verified identity claims were imported via OID4VP.
    ADD COLUMN IF NOT EXISTS identity_source_issuer TEXT,
    -- Timestamp of the last successful identity import.
    ADD COLUMN IF NOT EXISTS identity_imported_at TIMESTAMPTZ;
