-- 000150_public_score_token.up.sql
-- Adds a per-org public-score token (hashed) so ISVs can expose
-- their security compliance score to end customers without granting
-- full admin API access.
--
-- Token management: POST /compliance/score/public-token  (admin-only, Bearer JWT)
-- Public endpoint:  GET  /compliance/score/public        (Bearer clv_pub_... token)
ALTER TABLE conformance_scores
    ADD COLUMN IF NOT EXISTS public_score_token_hash   TEXT,
    ADD COLUMN IF NOT EXISTS public_score_token_prefix TEXT;
