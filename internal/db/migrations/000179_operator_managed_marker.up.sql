-- Declarative-management marker for resources owned by an external system
-- (today: the Clavex Kubernetes operator, k8s-operator). When a controller
-- creates or updates one of these resources it stamps managed_by/managed_ref
-- via the X-Clavex-Managed-By / X-Clavex-Managed-Ref request headers, so the
-- console and API can warn admins that out-of-band edits will be reverted at
-- the next reconcile.
--
-- Both columns are nullable and default NULL: an unmanaged resource (the vast
-- majority) carries no marker. managed_by is intentionally free-form text
-- ("k8s-operator" for now) rather than a boolean or enum, so future
-- declarative sources (GitOps, Terraform, ...) can reuse the same columns.
-- managed_ref is a human-readable pointer to the owning object
-- (e.g. "ClavexClient/clavex-operator-system/testclient" —
-- Kind/namespace/name of the CR) for debugging and a future deep link.
--
-- Marking rules live in the update handlers: only a request carrying the
-- X-Clavex-Managed-By header sets the columns; an ordinary update (UI,
-- clavexctl, direct API) never clears an existing marker. Management is
-- released explicitly (X-Clavex-Managed-Release header / the operator's
-- disown path), which clears the columns without touching the resource's
-- own configuration.

ALTER TABLE oidc_clients       ADD COLUMN managed_by TEXT, ADD COLUMN managed_ref TEXT;
ALTER TABLE roles              ADD COLUMN managed_by TEXT, ADD COLUMN managed_ref TEXT;
ALTER TABLE groups             ADD COLUMN managed_by TEXT, ADD COLUMN managed_ref TEXT;
ALTER TABLE org_auth_policies  ADD COLUMN managed_by TEXT, ADD COLUMN managed_ref TEXT;
ALTER TABLE webhooks           ADD COLUMN managed_by TEXT, ADD COLUMN managed_ref TEXT;
ALTER TABLE identity_providers ADD COLUMN managed_by TEXT, ADD COLUMN managed_ref TEXT;

-- ClavexOrg does not own a single "organizations" row; it reconciles the
-- org's password policy and rate-limit sections independently (either may be
-- managed while the other is not), so the marker lives on each section's row.
ALTER TABLE org_password_policy ADD COLUMN managed_by TEXT, ADD COLUMN managed_ref TEXT;
ALTER TABLE org_rate_limits     ADD COLUMN managed_by TEXT, ADD COLUMN managed_ref TEXT;
