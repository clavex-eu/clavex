ALTER TABLE oidc_clients DROP COLUMN IF EXISTS mfa_required;
ALTER TABLE oidc_clients DROP COLUMN IF EXISTS keycloak_compat;
