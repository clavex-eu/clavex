-- Migration 000055: remove the ghost refresh_tokens table in the identity
-- schema that shadows sessions.refresh_tokens in the search_path.
--
-- Root cause: same as migration 000054 (identity.authorization_codes).
-- An extra refresh_tokens table exists in the identity schema (first in
-- search_path), so all INSERTs hit identity.refresh_tokens which is missing
-- the user_agent, ip_address, device_name, last_seen_at columns added by
-- migration 000020.
--
-- sessions.refresh_tokens is the canonical table. Any rows in the identity
-- copy are unreachable by the application (they were inserted without the
-- required device-metadata columns), so it is safe to drop.

DROP TABLE IF EXISTS identity.refresh_tokens;
