-- Move all tables back to the public schema
ALTER TABLE identity.organizations          SET SCHEMA public;
ALTER TABLE identity.users                  SET SCHEMA public;
ALTER TABLE identity.roles                  SET SCHEMA public;
ALTER TABLE identity.role_members           SET SCHEMA public;
ALTER TABLE identity.user_roles             SET SCHEMA public;
ALTER TABLE identity.groups                 SET SCHEMA public;
ALTER TABLE identity.group_members          SET SCHEMA public;
ALTER TABLE identity.group_roles            SET SCHEMA public;
ALTER TABLE identity.oidc_clients           SET SCHEMA public;
ALTER TABLE identity.protocol_mappers       SET SCHEMA public;
ALTER TABLE identity.mfa_credentials        SET SCHEMA public;
ALTER TABLE identity.org_branding           SET SCHEMA public;
ALTER TABLE identity.org_smtp_settings      SET SCHEMA public;
ALTER TABLE identity.org_password_policy    SET SCHEMA public;
ALTER TABLE identity.org_email_domains      SET SCHEMA public;
ALTER TABLE identity.ldap_connections       SET SCHEMA public;
ALTER TABLE identity.saml_service_providers SET SCHEMA public;
ALTER TABLE identity.idp_certificates       SET SCHEMA public;
ALTER TABLE identity.webhooks               SET SCHEMA public;
ALTER TABLE identity.identity_providers     SET SCHEMA public;
ALTER TABLE identity.client_scopes          SET SCHEMA public;
ALTER TABLE identity.client_scope_assignments SET SCHEMA public;
ALTER TABLE identity.verification_tokens    SET SCHEMA public;

ALTER TABLE sessions.authorization_codes SET SCHEMA public;
ALTER TABLE sessions.refresh_tokens      SET SCHEMA public;

ALTER TABLE audit.audit_logs SET SCHEMA public;

DROP SCHEMA IF EXISTS identity;
DROP SCHEMA IF EXISTS sessions;
DROP SCHEMA IF EXISTS audit;
