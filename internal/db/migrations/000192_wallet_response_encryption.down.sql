DROP INDEX identity.presentation_response_key_expiry;
ALTER TABLE identity.presentation_sessions
    DROP COLUMN response_key_ciphertext,
    DROP COLUMN response_mode;
