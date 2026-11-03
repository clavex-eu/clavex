-- No status reference or trust is invented for historical credentials.
ALTER TABLE identity.issued_credentials ADD COLUMN issuer_jwt_hash TEXT;
CREATE UNIQUE INDEX issued_credential_issuer_jwt_idx ON identity.issued_credentials(org_id,issuer_jwt_hash) WHERE issuer_jwt_hash IS NOT NULL;
CREATE UNIQUE INDEX issued_credential_status_slot_idx ON identity.issued_credentials(org_id,status_list_id,status_index) WHERE status_list_id IS NOT NULL AND status_index IS NOT NULL;
CREATE UNIQUE INDEX credential_status_list_org_idx ON identity.credential_status_lists(org_id,id);
ALTER TABLE identity.issued_credentials ADD CONSTRAINT issued_credential_status_org_fk
    FOREIGN KEY(org_id,status_list_id) REFERENCES identity.credential_status_lists(org_id,id);
ALTER TABLE identity.issued_credentials ADD CONSTRAINT issued_credential_status_slot_check
    CHECK(status_index IS NULL OR status_index BETWEEN 0 AND 65535);
