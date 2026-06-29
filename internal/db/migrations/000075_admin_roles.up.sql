-- Delegated administration: per-org admin roles with granular permission sets.
-- Each admin_role holds a set of permission strings (e.g. "users:write",
-- "audit:read").  A user can be assigned one or more admin roles; their
-- effective permissions are the union of all assigned role permissions.
--
-- Backward compatibility: users with the existing "admin" system role in the
-- user_roles table and NO entries in admin_role_assignments continue to receive
-- full org-admin access (empty permissions = unrestricted).

CREATE TABLE IF NOT EXISTS admin_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    -- permissions is a sorted, de-duplicated array of permission strings.
    -- Known permission tokens are documented in internal/middleware/permissions.go.
    permissions TEXT[] NOT NULL DEFAULT '{}',
    -- system roles (created by Clavex) cannot be deleted.
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS admin_role_assignments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES identity.organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES identity.admin_roles(id) ON DELETE CASCADE,
    created_by UUID REFERENCES identity.users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_admin_roles_org        ON admin_roles(org_id);
CREATE INDEX IF NOT EXISTS idx_admin_ra_user          ON admin_role_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_ra_org           ON admin_role_assignments(org_id);
CREATE INDEX IF NOT EXISTS idx_admin_ra_role          ON admin_role_assignments(role_id);
