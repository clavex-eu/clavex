-- 000123_email_policy.up.sql
--
-- Adds per-org email domain blocklist and allowlist (Kinde-style anti-abuse).
--
-- email_blocklist: if non-empty, registration from any domain in this list is
--   refused.  Supports wildcard prefixes: "*.tempmail.com" or just "tempmail.com".
--
-- email_allowlist: if non-empty, only email addresses whose domain matches one
--   of the listed patterns are accepted.  Overrides the blocklist — i.e. if the
--   allowlist is set, the blocklist is ignored (allowlist wins).
--
-- Both arrays are per-org, so an ISV can configure stricter rules for their
-- tenants (e.g. "only @acme.com and @acme.eu can register").

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS email_blocklist text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS email_allowlist text[] NOT NULL DEFAULT '{}';
