-- OpenID Federation automatic client registration upserts the RP via
--   INSERT ... ON CONFLICT (org_id, (metadata->>'federation_entity_id')) DO UPDATE
-- (see ClientRepository.RegisterFederated). That ON CONFLICT inference needs a
-- matching unique index, which was never created — so every auto-register INSERT
-- failed with SQLSTATE 42P10 ("no unique or exclusion constraint matching the
-- ON CONFLICT specification") and surfaced to the RP as "unknown or inactive
-- client" at the authorization endpoint.
--
-- The index is on the org_id + extracted federation entity id expression. NULL
-- expression values (ordinary, non-federated clients) are distinct under a
-- unique index, so this only constrains rows that actually carry a
-- federation_entity_id; it does not affect manually registered clients.
CREATE UNIQUE INDEX IF NOT EXISTS oidc_clients_org_federation_entity_id_key
    ON oidc_clients (org_id, (metadata->>'federation_entity_id'));
