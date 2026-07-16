-- Org-scoped admin API keys.
--
-- Today every admin_api_keys row is implicitly superadmin-wide: it can call
-- any org's Admin API v2 endpoints (see internal/handler/admin_api_keys.go).
-- This adds an optional org_id: NULL keeps existing/legacy keys superadmin
-- (backward compatible), a non-NULL value scopes the key to exactly one
-- organization — the prerequisite for the Clavex Kubernetes Operator's
-- per-org Secret model (spec.authSecretRef), where the controller must never
-- hold cross-org credentials.
ALTER TABLE admin_api_keys
    ADD COLUMN org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Optional fine-grained permission scoping, reusing the same string-list
-- model already used for delegated-admin JWTs (middleware.Claims.Permissions).
-- NULL/empty = full access within `scope` (today's behaviour); a non-empty
-- list further restricts to specific permissions (e.g. "clients:write").
ALTER TABLE admin_api_keys
    ADD COLUMN permissions TEXT[];

-- Org-scoped keys must have a permission list scoped down; a superadmin key
-- (org_id IS NULL) may leave permissions NULL to mean "everything".
COMMENT ON COLUMN admin_api_keys.org_id IS
    'NULL = superadmin key (cross-org). Non-NULL = restricted to this org only.';
COMMENT ON COLUMN admin_api_keys.permissions IS
    'Optional fine-grained permission list (e.g. clients:write, idps:write). NULL = unrestricted within scope.';

CREATE INDEX idx_admin_api_keys_org_id
    ON admin_api_keys (org_id)
    WHERE org_id IS NOT NULL;
