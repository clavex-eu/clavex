-- Migration 000176: org-scoped OIDC rotation policy.
--
-- Now that every organisation signs with its own OIDC key (OrgSignerCache),
-- "rotate the OIDC key" means "rotate THAT org's key", not a shared global one.
-- So OIDC rotation policy becomes per-organisation, managed by the tenant's own
-- security admins.
--
-- PQC remains a process-global singleton (org_id IS NULL), still superadmin-only.
--
--   • org_id IS NULL      → global policy (PQC, and any legacy global OIDC row).
--   • org_id IS NOT NULL  → that org's OIDC rotation policy.

ALTER TABLE key_rotation_policies
    ADD COLUMN org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Replace the single-row-per-kind constraint with scope-aware partial indexes:
-- one global row per kind, and one row per (kind, org).
DROP INDEX IF EXISTS key_rotation_policies_kind;

CREATE UNIQUE INDEX key_rotation_policies_global
    ON key_rotation_policies (key_kind)
    WHERE org_id IS NULL;

CREATE UNIQUE INDEX key_rotation_policies_per_org
    ON key_rotation_policies (key_kind, org_id)
    WHERE org_id IS NOT NULL;
