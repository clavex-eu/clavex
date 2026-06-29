-- Migration 000054: remove the ghost authorization_codes table in the identity
-- schema that shadows sessions.authorization_codes in the search_path.
--
-- Root cause: at some point an extra authorization_codes table was created in
-- the identity schema (the first schema in search_path). Because identity
-- precedes sessions in SET search_path, all INSERTs hit identity.authorization_codes
-- which is missing the auth_time and authorization_details columns added by
-- migrations 000018 and 000041.
--
-- sessions.authorization_codes is the canonical table. The identity copy is
-- always empty (authorization codes expire in 10 minutes and are one-time-use)
-- so it is safe to drop without data loss.

DROP TABLE IF EXISTS identity.authorization_codes;
