-- Store only status references authenticated at issuance, never whole wallet JWTs.
ALTER TABLE identity.issued_credentials ADD COLUMN status_parents JSONB NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(status_parents)='array');
ALTER TABLE identity.issued_credentials ADD COLUMN parents_checked_at TIMESTAMPTZ;
ALTER TABLE identity.issued_credentials ADD COLUMN parent_status_hold BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE identity.deferred_credentials ADD COLUMN status_parents JSONB NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(status_parents)='array');
CREATE INDEX issued_credential_parent_poll_idx ON identity.issued_credentials(parents_checked_at NULLS FIRST,id)
WHERE NOT is_revoked AND status_parents<>'[]'::jsonb;
