-- 000002_add_org_domain_allowlist.up.sql
-- Esempio: aggiunge una tabella per i domini email autorizzati per org
-- (utile per SSO automatico: se l'email è @inwit.it → org INWIT)

CREATE TABLE org_email_domains (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,              -- e.g. "inwit.it"
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, domain)
);

CREATE INDEX idx_org_email_domains_domain ON org_email_domains(domain);
