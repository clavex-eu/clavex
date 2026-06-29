-- RFC 8693 §2.1: allowed target audiences for the token-exchange grant.
-- When a token-exchange request carries a `resource`/`audience` parameter, the
-- requested value MUST be present in this list (or equal the calling client_id);
-- otherwise the request is rejected with error=invalid_target. An empty list
-- means the client may only obtain tokens audienced to itself.
ALTER TABLE oidc_clients
    ADD COLUMN allowed_audiences TEXT[] NOT NULL DEFAULT '{}';
