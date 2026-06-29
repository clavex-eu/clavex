-- 000119_cross_org_trust_policy.up.sql
--
-- Adds scoping-policy fields to cross_org_trusts so that token exchange can be
-- restricted beyond just scope/client_id:
--
--   max_token_ttl  — upper bound (seconds) on the exchanged access-token lifetime.
--                    NULL means "use the server default TTL".
--   require_mfa    — when TRUE the subject_token must carry an amr claim that
--                    includes at least one MFA method (otp/totp/hwk/swk/phr/mfa).
--                    Without this the exchange is rejected with access_denied.
--
-- Together these turn the binary allow/deny trust into a proper policy object.

ALTER TABLE cross_org_trusts
    ADD COLUMN max_token_ttl INTEGER DEFAULT NULL,
    ADD COLUMN require_mfa   BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN cross_org_trusts.max_token_ttl IS
    'Maximum lifetime in seconds for tokens issued via this trust. NULL = server default.';
COMMENT ON COLUMN cross_org_trusts.require_mfa IS
    'When TRUE, the subject_token must prove MFA (amr ∋ {otp,totp,hwk,swk,phr,mfa}).';
