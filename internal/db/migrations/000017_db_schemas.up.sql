-- DB schema separation: move tables into dedicated schemas for better separation
-- of concerns and access control.
--
-- Schemas:
--   identity  → organisations, users, roles, credentials, groups, clients, mappers, etc.
--   sessions  → transient tokens (auth codes, refresh tokens)
--   audit     → append-only audit log

CREATE SCHEMA IF NOT EXISTS identity;
CREATE SCHEMA IF NOT EXISTS sessions;
CREATE SCHEMA IF NOT EXISTS audit;

-- ── identity schema ────────────────────────────────────────────────────────────
ALTER TABLE organizations          SET SCHEMA identity;
ALTER TABLE users                  SET SCHEMA identity;
ALTER TABLE roles                  SET SCHEMA identity;
ALTER TABLE role_members           SET SCHEMA identity;
ALTER TABLE user_roles             SET SCHEMA identity;
ALTER TABLE groups                 SET SCHEMA identity;
ALTER TABLE group_members          SET SCHEMA identity;
ALTER TABLE group_roles            SET SCHEMA identity;
ALTER TABLE oidc_clients           SET SCHEMA identity;
ALTER TABLE protocol_mappers       SET SCHEMA identity;
ALTER TABLE mfa_credentials        SET SCHEMA identity;
ALTER TABLE org_branding           SET SCHEMA identity;
ALTER TABLE org_smtp_settings      SET SCHEMA identity;
ALTER TABLE org_password_policy    SET SCHEMA identity;
ALTER TABLE org_email_domains      SET SCHEMA identity;
ALTER TABLE ldap_connections       SET SCHEMA identity;
ALTER TABLE saml_service_providers SET SCHEMA identity;
ALTER TABLE idp_certificates       SET SCHEMA identity;
ALTER TABLE webhooks               SET SCHEMA identity;
ALTER TABLE identity_providers     SET SCHEMA identity;
ALTER TABLE client_scopes          SET SCHEMA identity;
ALTER TABLE client_scope_assignments SET SCHEMA identity;
ALTER TABLE verification_tokens    SET SCHEMA identity;

-- ── sessions schema ────────────────────────────────────────────────────────────
ALTER TABLE authorization_codes SET SCHEMA sessions;
ALTER TABLE refresh_tokens      SET SCHEMA sessions;

-- ── audit schema ───────────────────────────────────────────────────────────────
ALTER TABLE audit_logs SET SCHEMA audit;

-- Allow the application role to use all three schemas.
-- Adjust 'clavex' to match your actual DB user/role name.
GRANT USAGE ON SCHEMA identity TO clavex;
GRANT USAGE ON SCHEMA sessions TO clavex;
GRANT USAGE ON SCHEMA audit   TO clavex;
GRANT ALL   ON ALL TABLES IN SCHEMA identity TO clavex;
GRANT ALL   ON ALL TABLES IN SCHEMA sessions TO clavex;
GRANT ALL   ON ALL TABLES IN SCHEMA audit   TO clavex;
GRANT ALL   ON ALL SEQUENCES IN SCHEMA identity TO clavex;
GRANT ALL   ON ALL SEQUENCES IN SCHEMA sessions TO clavex;
GRANT ALL   ON ALL SEQUENCES IN SCHEMA audit   TO clavex;
