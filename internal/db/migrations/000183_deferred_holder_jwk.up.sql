-- Persist only the public holder key authenticated during the initial request.
-- Legacy rows remain NULL and require a new issuance request before approval.
ALTER TABLE identity.deferred_credentials
    ADD COLUMN holder_jwk JSONB,
    ADD CONSTRAINT deferred_holder_jwk_public CHECK (
        holder_jwk IS NULL OR (
            jsonb_typeof(holder_jwk) = 'object'
            AND holder_jwk->>'kty' IS NOT NULL
            AND holder_jwk->>'kty' IN ('EC', 'RSA')
            AND NOT (holder_jwk ?| ARRAY['d','p','q','dp','dq','qi','oth','k'])
        )
    );
