-- 001_initial_schema.sql : Core schema for clavex

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────
-- Organizations (tenants)
-- ─────────────────────────────────────────────
CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,           -- used as subdomain: {slug}.clavex.eu
    logo_url    TEXT,
    settings    JSONB NOT NULL DEFAULT '{}',
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- Users
-- ─────────────────────────────────────────────
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email               TEXT NOT NULL,
    password_hash       TEXT,                   -- NULL for federation-only users
    first_name          TEXT,
    last_name           TEXT,
    avatar_url          TEXT,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    is_email_verified   BOOLEAN NOT NULL DEFAULT FALSE,
    metadata            JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at       TIMESTAMPTZ,
    UNIQUE(org_id, email)
);

CREATE INDEX idx_users_org_id ON users(org_id);
CREATE INDEX idx_users_email ON users(email);

-- ─────────────────────────────────────────────
-- Roles
-- ─────────────────────────────────────────────
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT FALSE, -- system roles cannot be deleted
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, name)
);

CREATE TABLE user_roles (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- ─────────────────────────────────────────────
-- OIDC Clients (registered applications)
-- ─────────────────────────────────────────────
CREATE TABLE oidc_clients (
    client_id               TEXT PRIMARY KEY,
    org_id                  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_secret_hash      TEXT,               -- NULL for public clients
    name                    TEXT NOT NULL,
    redirect_uris           TEXT[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types             TEXT[] NOT NULL DEFAULT '{authorization_code}',
    response_types          TEXT[] NOT NULL DEFAULT '{code}',
    scopes                  TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
    logo_url                TEXT,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    metadata                JSONB NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oidc_clients_org_id ON oidc_clients(org_id);

-- ─────────────────────────────────────────────
-- MFA credentials
-- ─────────────────────────────────────────────
CREATE TABLE mfa_credentials (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL CHECK (type IN ('totp', 'webauthn')),
    name        TEXT NOT NULL DEFAULT 'default',
    data        JSONB NOT NULL,                 -- TOTP secret or WebAuthn credential
    is_primary  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_user_id ON mfa_credentials(user_id);

-- ─────────────────────────────────────────────
-- LDAP / Identity Provider connections (per org)
-- ─────────────────────────────────────────────
CREATE TABLE ldap_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    host            TEXT NOT NULL,
    port            INT NOT NULL DEFAULT 389,
    use_tls         BOOLEAN NOT NULL DEFAULT FALSE,
    bind_dn         TEXT,
    bind_password   TEXT,                       -- encrypted at rest
    base_dn         TEXT NOT NULL,
    user_filter     TEXT NOT NULL DEFAULT '(objectClass=person)',
    user_attr_map   JSONB NOT NULL DEFAULT '{"email":"mail","first_name":"givenName","last_name":"sn"}',
    is_active       BOOLEAN NOT NULL DEFAULT FALSE,
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- SAML Service Providers (apps that use our IdP)
-- ─────────────────────────────────────────────
CREATE TABLE saml_service_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    entity_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    acs_url         TEXT NOT NULL,              -- Assertion Consumer Service URL
    slo_url         TEXT,                       -- Single Logout URL
    metadata_xml    TEXT,                       -- SP metadata XML
    name_id_format  TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, entity_id)
);

-- ─────────────────────────────────────────────
-- Audit log
-- ─────────────────────────────────────────────
CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    org_id          UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email     TEXT,                       -- snapshot of email at time of action
    action          TEXT NOT NULL,              -- e.g. user.login, client.created
    resource_type   TEXT,
    resource_id     TEXT,
    status          TEXT NOT NULL DEFAULT 'success' CHECK (status IN ('success', 'failure')),
    ip_address      INET,
    user_agent      TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_org_id ON audit_logs(org_id, created_at DESC);
CREATE INDEX idx_audit_user_id ON audit_logs(user_id, created_at DESC);

-- ─────────────────────────────────────────────
-- Email verification tokens
-- ─────────────────────────────────────────────
CREATE TABLE verification_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL CHECK (type IN ('email_verify', 'password_reset', 'invite')),
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_tokens_hash ON verification_tokens(token_hash);
