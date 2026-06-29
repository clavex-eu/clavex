-- RFC 9449 §5: dpop_bound_access_tokens client metadata.
-- When TRUE the token endpoint MUST require a DPoP proof for every token
-- request, regardless of whether dpop_jkt was bound in the authorization code.
ALTER TABLE oidc_clients
    ADD COLUMN dpop_bound_access_tokens BOOLEAN NOT NULL DEFAULT FALSE;
