-- Track who authored a delegated admin role.
--
-- admin_role_assignments already records the assigner (created_by), but the
-- admin_roles table had no author reference — so there was no way to know which
-- admin minted a given role (relevant now that role creation enforces
-- non-escalation against the creator's own permissions).
--
-- Nullable + ON DELETE SET NULL, mirroring every other created_by in the schema
-- (e.g. 000021_scim_tokens, 000023_ip_allowlist). Existing rows stay NULL: the
-- author of pre-existing roles was never recorded and cannot be reconstructed.
ALTER TABLE admin_roles
    ADD COLUMN created_by UUID REFERENCES identity.users(id) ON DELETE SET NULL;

COMMENT ON COLUMN admin_roles.created_by IS
    'User who created the role. NULL for system roles and for roles created before this column existed.';
