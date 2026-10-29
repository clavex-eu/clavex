ALTER TABLE identity.deferred_credentials
    DROP CONSTRAINT deferred_holder_jwk_public,
    DROP COLUMN holder_jwk;
