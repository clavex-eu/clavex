-- 000001_initial_schema.down.sql : Rollback dello schema iniziale

DROP TABLE IF EXISTS verification_tokens;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS saml_service_providers;
DROP TABLE IF EXISTS ldap_connections;
DROP TABLE IF EXISTS mfa_credentials;
DROP TABLE IF EXISTS oidc_clients;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;
