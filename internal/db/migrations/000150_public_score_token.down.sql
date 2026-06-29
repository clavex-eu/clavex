-- 000150_public_score_token.down.sql
ALTER TABLE conformance_scores
    DROP COLUMN IF EXISTS public_score_token_hash,
    DROP COLUMN IF EXISTS public_score_token_prefix;
