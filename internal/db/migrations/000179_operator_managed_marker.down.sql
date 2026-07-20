ALTER TABLE oidc_clients        DROP COLUMN IF EXISTS managed_by, DROP COLUMN IF EXISTS managed_ref;
ALTER TABLE roles               DROP COLUMN IF EXISTS managed_by, DROP COLUMN IF EXISTS managed_ref;
ALTER TABLE groups              DROP COLUMN IF EXISTS managed_by, DROP COLUMN IF EXISTS managed_ref;
ALTER TABLE org_auth_policies   DROP COLUMN IF EXISTS managed_by, DROP COLUMN IF EXISTS managed_ref;
ALTER TABLE webhooks            DROP COLUMN IF EXISTS managed_by, DROP COLUMN IF EXISTS managed_ref;
ALTER TABLE identity_providers  DROP COLUMN IF EXISTS managed_by, DROP COLUMN IF EXISTS managed_ref;
ALTER TABLE org_password_policy DROP COLUMN IF EXISTS managed_by, DROP COLUMN IF EXISTS managed_ref;
ALTER TABLE org_rate_limits     DROP COLUMN IF EXISTS managed_by, DROP COLUMN IF EXISTS managed_ref;
