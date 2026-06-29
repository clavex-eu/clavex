# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| Any release < 6 months old | ✅ |
| Older releases | ❌ — please upgrade |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues via one of the following channels:

### GitHub Private Security Advisory (preferred)
Use GitHub's built-in [private vulnerability reporting](../../security/advisories/new) feature.  
This keeps the disclosure confidential until a fix is merged and released.

### Email
Send a GPG-encrypted email to **security@clavex.eu** with:
- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code or a curl command is helpful)
- Any suggestions for a fix

Our PGP public key is available at [https://clavex.eu/.well-known/pgp-key.txt](https://clavex.eu/.well-known/pgp-key.txt).

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement of report | Within **48 hours** |
| Initial triage and severity assessment | Within **5 business days** |
| Fix developed and reviewed | Within **30 days** for Critical/High; **90 days** for Medium/Low |
| Coordinated public disclosure | After fix is released and deployers have had time to update (typically 14–30 days post-patch) |

We follow a **coordinated disclosure** model. We will credit reporters in the release notes unless they request anonymity.

---

## CVE Response Process

This section documents our end-to-end vulnerability management workflow.
It exists so that the process is transparent, auditable, and executable without tribal knowledge.

### Step 1 — Report intake

All reports are received via GitHub Private Security Advisories or **security@clavex.eu**.
A member of the security team acknowledges receipt within **48 hours** and assigns an internal tracking ID (`CLAVEX-YYYY-NNN`).

### Step 2 — Triage

Within **5 business days** the security team:

1. Reproduces the issue in a local environment (or confirms it from the report).
2. Assigns a [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) base score.
3. Assigns severity: Critical / High / Medium / Low.
4. Decides on the remediation timeline (see table above).
5. Notifies the reporter of the outcome.

### Step 3 — Fix & internal review

1. A fix is developed in a **private branch** (GitHub draft advisory + private fork).
2. The fix undergoes a security-focused code review by a second team member.
3. Unit + integration tests are added that would have caught the original vulnerability.
4. The fix is merged to `main` under a `[security]` commit subject.

### Step 4 — Release

1. A new patch version is tagged and pushed.
2. The Docker image is rebuilt and pushed to `ghcr.io`.
3. The GitHub Security Advisory is published, which triggers an automatic CVE request
   through GitHub's CVE Numbering Authority (CNA) partnership.
4. A CVE ID is requested if not automatically assigned. We use GitHub's CNA for all
   Clavex-specific vulnerabilities.

### Step 5 — Public disclosure

1. The GitHub Security Advisory is made public.
2. A summary entry is added to [`security/advisories/`](security/advisories/).
3. The release notes (`CHANGELOG.md`) reference the advisory and CVE.
4. The reporter is credited (unless they requested anonymity).

### Advisories index

All published advisories live in [`security/advisories/`](security/advisories/).
Each file follows the naming convention `CLAVEX-YYYY-NNN.md`.

| ID | Severity | Summary | Fixed in |
|----|----------|---------|----------|
| [CLAVEX-2026-001](security/advisories/CLAVEX-2026-001.md) | Low | Debug log disclosure of `login_hint` sub claim (CIBA) | pre-release, never shipped |

---

## Scope

### In scope
- Authentication and authorization bypasses
- JWT / SD-JWT forgery or algorithm confusion attacks
- OIDC/OAuth2 protocol violations that allow token theft or impersonation
- SAML assertion injection or signature bypass
- SQL injection or other DB-layer vulnerabilities
- SSRF in webhook dispatchers or IdP connectors
- Privilege escalation (tenant A accessing tenant B's data)
- Secrets leakage in API responses, logs, or error messages
- Denial of service vulnerabilities that bypass per-org rate limiting

### Out of scope
- Vulnerabilities in third-party dependencies that are not exploitable in Clavex
- Social engineering attacks
- Physical attacks against the host server
- Rate limiting bypasses that require an attacker to already have valid admin credentials
- `config.dev.yaml` containing example weak secrets (do not use these in production)

---

## Severity Assessment

We use [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) for severity scoring, supplemented by business context:

| CVSS Score | Severity | Example |
|------------|----------|---------|
| 9.0 – 10.0 | **Critical** | Unauthenticated RCE, full tenant isolation bypass |
| 7.0 – 8.9 | **High** | Auth bypass, token forgery, cross-tenant data access |
| 4.0 – 6.9 | **Medium** | Privilege escalation within a tenant, information disclosure |
| 0.1 – 3.9 | **Low** | Rate limit bypass with valid credentials, minor info leak |

---

## Security Hardening Checklist (for operators)

Before deploying to production:

- [ ] Generate a new RSA 2048+ signing key (`openssl genrsa -out keys/signing.pem 2048`)
- [ ] Set `auth.admin_secret` to a random value of ≥ 32 bytes
- [ ] Enable TLS (`http.tls_cert_file` / `http.tls_key_file`)
- [ ] Set `http.cors_allowed_origins` to your actual frontend domain(s)
- [ ] Configure per-org rate limits via `PUT /api/v1/organizations/:id/rate-limits`
- [ ] Enable MFA for all admin accounts
- [ ] Configure audit log retention and at least one sink (webhook / SIEM)
- [ ] Restrict database access to the Clavex service account only
- [ ] Run Clavex as a non-root user inside the container

---

## Known Security Properties

### Multi-tenancy isolation
Every database query is scoped to `org_id`. The `RequireOrgAccess()` middleware enforces this at the HTTP layer. Super-admin tokens are not used for tenant operations.

### Token security
- Access tokens are RS256-signed JWTs (2048-bit RSA minimum)
- Refresh tokens are random 32-byte opaque values stored as SHA-256 hashes
- Pre-authorized codes (OID4VCI) are single-use and expire after 15 minutes by default
- SD-JWT-VC credentials are signed with the same key as OIDC tokens; each credential includes a non-reversible SHA-256 audit hash

### Rate limiting
Per-org rate limiting uses a Redis sliding-window counter. Limits are:
- **10 login attempts / IP / minute** (default; configurable)
- **60 token requests / client_id / minute** (default; configurable)
- **120 requests / IP / minute** global per tenant (default; configurable)

A tenant under brute-force attack will not affect other tenants.

### Audit trail integrity
The `login_history` table is append-only. DB-level triggers keep `last_login_at` denormalised. Audit records include IP, user-agent, and optional country/ASN for anomaly detection.
