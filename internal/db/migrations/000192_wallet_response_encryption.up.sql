ALTER TABLE identity.presentation_sessions
    ADD COLUMN response_mode text NOT NULL DEFAULT 'direct_post'
        CHECK (response_mode IN ('direct_post', 'direct_post.jwt')),
    ADD COLUMN response_key_ciphertext bytea;

CREATE INDEX presentation_response_key_expiry
    ON identity.presentation_sessions (expires_at)
    WHERE response_key_ciphertext IS NOT NULL;
