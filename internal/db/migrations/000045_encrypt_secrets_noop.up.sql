-- Migration 000045: Encryption at rest for LDAP passwords, SCIM bearer tokens,
-- and webhook secrets.
--
-- This is a schema no-op. The actual re-encryption of existing plaintext values
-- is performed by the Go application at startup using the crypto.Encryptor helper
-- (internal/crypto/secrets.go). The Decrypt() helper auto-detects plaintext
-- and returns it unchanged, so old rows work immediately after deploy.
-- A background startup task can be added to re-encrypt all rows in bulk if needed.
SELECT 1;
