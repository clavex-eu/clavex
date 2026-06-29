-- 000096_idp_promoted.up.sql
-- Mark an identity provider as "promoted": it appears as a prominent full-width
-- button on the login page instead of a small icon, above the email/password form.
ALTER TABLE identity_providers
    ADD COLUMN IF NOT EXISTS is_promoted BOOLEAN NOT NULL DEFAULT FALSE;

-- At most one promoted IdP per org is recommended (not enforced by DB — the
-- login page renders all promoted ones but de-emphasises extras).
