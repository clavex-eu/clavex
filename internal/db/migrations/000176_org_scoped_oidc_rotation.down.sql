DROP INDEX IF EXISTS key_rotation_policies_per_org;
DROP INDEX IF EXISTS key_rotation_policies_global;
-- Remove per-org rows before restoring the global-only unique constraint.
DELETE FROM key_rotation_policies WHERE org_id IS NOT NULL;
ALTER TABLE key_rotation_policies DROP COLUMN org_id;
CREATE UNIQUE INDEX key_rotation_policies_kind ON key_rotation_policies (key_kind);
