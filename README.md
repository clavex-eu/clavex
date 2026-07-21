# Clavex

<!-- Conformance badges — auto-updated by nightly CI from CONFORMANCE.md -->
[![FAPI 2.0](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fclavex%2Fmain%2Fconformance-fapi-badge.json)](CONFORMANCE.md)
[![JARM](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fclavex%2Fmain%2Fconformance-jarm-badge.json)](CONFORMANCE.md)
[![mTLS](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fclavex%2Fmain%2Fconformance-mtls-badge.json)](CONFORMANCE.md)
[![OID4VCI](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fclavex%2Fmain%2Fconformance-oid4vci-badge.json)](CONFORMANCE.md)
[![OID4VP](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fclavex%2Fmain%2Fconformance-oid4vp-badge.json)](CONFORMANCE.md)
[![HAIP](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fclavex%2Fmain%2Fconformance-haip-badge.json)](CONFORMANCE.md)
[![FAPI-CIBA](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fclavex%2Fmain%2Fconformance-ciba-badge.json)](CONFORMANCE.md)
[![OpenID Federation](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fclavex%2Fmain%2Fconformance-federation-badge.json)](CONFORMANCE.md)
[![OIDC Conformance](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fclavex%2Fmain%2Fconformance-badge.json)](CONFORMANCE.md)
[![Auth uptime](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fupptime%2FHEAD%2Fapi%2Fauth%2Fuptime.json)](https://status.clavex.eu)
[![Auth response time](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fclavex-eu%2Fupptime%2FHEAD%2Fapi%2Fauth%2Fresponse-time.json)](https://status.clavex.eu)
[![Discord](https://img.shields.io/discord/1522651912183480533?label=Discord&logo=discord&logoColor=white&color=5865F2)](https://discord.gg/WT8pRXHgjC)

**Clavex** is a self-hosted, open-core Identity & Access Management platform built for modern infrastructure. It speaks OIDC/OAuth 2.0, SAML 2.0, SCIM 2.0, FAPI 2.0, and the EU Digital Identity Wallet stack (eIDAS 2.0).

> Built in Go. Multi-tenant from day one. Runs inside your perimeter — no vendor lock-in, no data leaving your control.

---

## Quick Start

```bash
# Scaffold a Next.js / React app wired to Clavex in < 5 minutes
npx create-clavex-app myapp

# — or — self-host the server
openssl genrsa -out keys/signing.pem 2048
cp config.example.yaml config.dev.yaml
docker compose up -d   # Postgres + Redis + Clavex at :8080
```

Full quickstart: [docs.clavex.eu](https://docs.clavex.eu) · API reference: `/api/v1/openapi.json`

---

## Features

### 🔐 Core IAM
| Feature | Notes |
|---|---|
| **OIDC / OAuth 2.0** | Auth Code + PKCE, Client Credentials, Device Flow, Refresh Token, Introspection, Revocation |
| **SAML 2.0** | SP-initiated SSO/SLO, IdP-initiated flow, JIT provisioning, encrypted assertions |
| **SCIM 2.0** | Full user + group provisioning (Okta, Entra ID, any SCIM IdP); SCIM Push to downstream apps |
| **Multi-tenancy** | Hard DB-level isolation; every org gets its own issuer URL, client registry, and user pool |
| **Social / OIDC Federation** | Connect any OAuth2/OIDC provider (Google, GitHub, Azure, Keycloak, …) |
| **MFA** | TOTP (RFC 6238, QR endpoint) · SMS OTP · Email OTP · Passkeys · 10 one-time backup codes |
| **Passkeys + FIDO2** | WebAuthn Conditional UI (MediationConditional), FIDO MDS3 attestation catalog, per-org policy |
| **Groups & Roles** | Composite roles, group-to-role mapping, custom protocol mappers, admin delegation |
| **Session management** | Redis-backed sessions, concurrent session limit, device list, remote revocation |
| **Forward Auth Proxy** | Drop-in auth layer for nginx / Traefik / Caddy |
| **Impersonation** | Admin can impersonate any user; full audit trail |
| **Bulk Import** | CSV / JSON user import with password hashing |
| **LDAP** | Read-only LDAP directory connector with attribute mapping |

### 🇪🇺 EU Digital Identity
| Feature | Notes |
|---|---|
| **SPID** | All 9 AgID-registered IdPs; SAML2 + XML-DSig SP; LoA1/2/3 — **production use requires AgID SP accreditation** (see below) |
| **CIE** | Carta d'Identità Elettronica OIDC 3.0 (IPZS prod + preprod); JIT provisioning — requires registration at Ministero dell'Interno developer portal |
| **FranceConnect** | v2 — 45M French users; eIDAS assurance levels 1/2/3 — sandbox available without approval; production requires DINUM convention |
| **BundID** | German federal identity (BSI TR-03107); OIDC — FITKO portal registration; SoftID simulator for CI/CD |
| **Cl@ve** | Spanish national identity (FNMT/SGAD); LoA1/LoA2/LoA3 — pre-production requires registration; SGAD issues `client_id` after SP metadata submission |
| **DigiD** | Dutch national identity; LoA2/LoA3 — formal Logius admission process including security audit; BSN use requires legal basis (Wabb Art. 10) |
| **itsme®** | Belgian/Luxembourg OIDC identity; LoA2/LoA3 — commercial partnership with Belgian Mobile ID SA; sandbox after signup |
| **OID4VCI** | SD-JWT-VC credential issuance; pre-authorized code flow; transaction codes; QR deep-links |
| **OID4VP** | Presentation Exchange v2; `direct_post`; StatusList2021 revocation |
| **OpenID IDA** | `verified_claims` in every ID token / UserInfo; trust framework + evidence record per IdP |
| **OpenID Federation** | Entity Statement publishing; federation metadata endpoint |

### EU Identity Provider — Production Requirements

Some EU eID integrations require prior registration or accreditation with the respective national authority before production use. Development and test environments are generally available without prior approval.

| Provider | Dev / Test | Production | Registration |
|---|---|---|---|
| **SPID** (Italy) | ✅ `demo.spid.gov.it` — no approval needed | ❌ Required | AgID SP accreditation — legal entity required, 4–8 weeks. Details: [agid.gov.it](https://www.agid.gov.it/it/piattaforme/spid) |
| **CIE** (Italy) | ✅ `preproduzione.idserver.servizicie.interno.gov.it` — no approval needed | ⚠️ Required | Register `client_id` + `redirect_uri` at Ministero dell'Interno developer portal |
| **FranceConnect** | ✅ Public sandbox — no approval needed | ⚠️ Required | DINUM approval + convention — approx. 2–4 weeks. [franceconnect.gouv.fr](https://franceconnect.gouv.fr) |
| **BundID** (Germany) | ✅ FITKO portal request — lightweight access | ⚠️ Required | Register via FITKO support portal; SoftID simulator available for CI/CD |
| **Cl@ve** (Spain) | ⚠️ Pre-production requires registration | ⚠️ Required | Submit SP metadata XML to SGAD; SGAD issues `client_id` and approves redirect URIs |
| **DigiD** (Netherlands) | ⚠️ Test accounts only, no real BSNs | ❌ Required | Logius formal admission process ("Toelatingsproces") including security audit. BSN use requires legal basis (Wabb Art. 10) |
| **itsme®** (Belgium/LU) | ⚠️ Sandbox after signup at brand.belgianmobileid.be | ❌ Required | Partnership agreement with Belgian Mobile ID SA (commercial) |
| **FAPI 2.0 / Open Banking** | ✅ No external registration | ✅ No external registration | Bank API access depends on individual bank agreements — Clavex provides the conformant AS/IdP |
| **OID4VCI / OID4VP / mdoc** | ✅ No registration | ✅ No registration | QTSP accreditation only required for legally-binding EU-level credentials. Internal/enterprise credentials work without accreditation |
| **PAM / HashiCorp Vault** | ✅ Optional — file backend works standalone | ✅ Optional | Vault required only if `CLAVEX_KEY_BACKEND=vault`; default `file` backend needs no external service |

> **Italian PA note:** SPID accreditation is managed by AgID and is mandatory for production. Full integration testing (including the complete SAML flow, attribute mapping, and LoA upgrade) can be done against `demo.spid.gov.it` and `preproduzione.idserver.servizicie.interno.gov.it` without any prior registration.

### 🏦 FAPI 2.0 / Open Banking
| Feature | Notes |
|---|---|
| **JAR** (RFC 9101) | Signed request objects; PAR endpoint |
| **PAR** (RFC 9126) | Pushed Authorization Requests; mandatory for FAPI 2.0 |
| **DPoP** (RFC 9449) | Sender-constrained access tokens; Redis jti anti-replay |
| **JARM** | JWT-secured authorization responses (signed + encrypted) |
| **mTLS** | Mutual TLS client authentication; certificate-bound tokens |
| **PKCE** | S256 code challenge; enforced for public clients |
| **Conformance** | See [CONFORMANCE.md](CONFORMANCE.md) for full OIDF suite results |

### 🛡️ Threat Intelligence & Risk
| Feature | Notes |
|---|---|
| **Clavex Shield** | Composite 0–100 risk score: IP reputation, impossible travel, new country, datacenter ASN, new device, unusual hour |
| **Clavex Guard** | Adaptive lockout — low-risk fat-finger → 30 s; Tor exit node in new country → 60 min; per-org thresholds |
| **Breached Passwords** | HIBP k-anonymity check at login + per-org breach report |
| **Captcha** | hCaptcha / Cloudflare Turnstile per org; triggered by risk score |
| **GeoIP** | Country + ASN enrichment on every login event |
| **Login Intelligence** | Per-user login timeline; anomaly surface; impossible travel alerts |

### 🔑 Privileged Access (PAM)
| Feature | Notes |
|---|---|
| **JIT Access** | Time-boxed access requests with approval workflow |
| **Credential Vault** | AES-256-GCM encrypted secrets; one-shot checkout with audit |
| **Vault SSH CA** | HashiCorp Vault integration — ephemeral SSH certificates; no agent on endpoints |
| **Session Recording** | Privileged session audit log |

### ⚖️ Authorization
| Feature | Notes |
|---|---|
| **AuthZen 1.0** | Standards-compliant PDP + PIP evaluation endpoint |
| **Fine-Grained AuthZ** | OpenFGA-compatible tuple store; Check / Write / Read / model editor |
| **RBAC** | Role-based access control with composite roles and group mappings |
| **Policy Engine** | CEL-based policy expressions; visual policy editor; batch simulation |

### 📋 Compliance
| Feature | Notes |
|---|---|
| **GDPR Art.30 RoPA** | Article 30 Records of Processing Activities — REST API + admin UI |
| **NIS2 Art.21** | Evidence package export for incident reporting |
| **DSAR** | Complete personal data export per user (Data Subject Access Request) |
| **ACID Event Store** | Append-only `entity_events` table; actor attribution; point-in-time reconstruction |
| **Clavex Ledger** | SHA-256 Merkle-hash chain over audit batches; RS256-signed; offline verifiable |
| **Lifecycle Rules** | Automated user lifecycle: dormancy → warning → disable → delete |
| **Access Reviews** | Scheduled campaign review of role/group assignments with approve/revoke decisions |
| **Entity Review** | Periodic review campaigns for clients, groups, and roles |

### 🏢 B2B / ISV / Multi-tenant SaaS
| Feature | Notes |
|---|---|
| **Cross-Org Trust** | Outbound trust to partner orgs; scope + client-ID allow-lists; RFC 8693 Token Exchange |
| **App Families** | Group apps for shared SSO session across a product suite |
| **Domain Enrollment** | `@company.com` email auto-joins users to the right org |
| **Self-Serve Admin Portal** | IT admins configure SSO, SCIM, domains, MFA autonomously |
| **Custom Login** | Per-org branded HTML login page; live preview; instant revert |
| **Per-Tenant Rate Limits** | Redis sliding-window rate limits per org on login + token endpoints |
| **SCIM Push** | Push user/group changes to downstream SaaS apps |
| **WS-Federation** | Native WS-Fed IdP for SharePoint Online, ADFS, PA / public-sector |

### 🤖 AI-Ready / Agentic Identity
| Feature | Notes |
|---|---|
| **Agent Tokens** | Machine identity with `delegated_by` + `agent_id` claims for human-in-the-loop attribution |
| **MCP OAuth AS** | OAuth 2.0 Authorization Server for Model Context Protocol servers |
| **AI flow step** | `ai_decision` step injects real-time AI risk scoring into any login flow |
| **Service Accounts** | First-class M2M identities with `last_used_at` tracking and scope constraints |

### 📡 Event Streaming
| Feature | Notes |
|---|---|
| **SSF / CAEP / RISC** | Push `session.revoked`, `credential-change`, `token-claims-change` to connected apps in real time |
| **CAE Token Push** | RFC 9700 Continuous Access Evaluation |
| **Webhooks** | Async HTTP fan-out with retry + delivery log |
| **MQTT** | Native IoT/embedded event sink |
| **Kafka** | Direct Kafka producer for SIEM and analytics pipelines |
| **SIEM sinks** | Splunk HEC, Elastic ECS, Azure Sentinel, Datadog |

### 🧰 Developer Experience
| Feature | Notes |
|---|---|
| **create-clavex-app** | `npx create-clavex-app myapp` — Next.js / React scaffold with OIDC wired in < 5 min |
| **Prometheus / OTel** | Per-org login counters, token-issue rates, risk-score histograms, HTTP latency |
| **SBOM** | CycloneDX SBOM on every CI push via Syft (EU CRA compliance) |
| **Login Flows** | Visual no-code login flow builder — attribute checks, MFA gates, IP risk, claim enrichment |
| **Actions V2** | Event hooks (JavaScript) on any user / auth API event |
| **Onboarding Wizard** | Step-by-step guided setup for new orgs |

---

## Architecture

```
cmd/server/          — binary entrypoint (Echo)
internal/
  config/            — YAML + env config loader
  db/migrations/     — ordered SQL migrations (golang-migrate)
  handler/           — Echo HTTP handlers (one file per domain)
  middleware/        — JWT auth, per-org rate limiting, request logging
  models/            — shared Go structs (no ORM)
  oidc/              — OIDC/OAuth 2.0 protocol logic (JAR, PAR, DPoP, JARM, PKCE)
  oid4w/             — SD-JWT-VC, OID4VCI, OID4VP (eIDAS 2.0)
  repository/        — pgx query layer (one file per domain)
  saml/              — SAML 2.0 SP/IdP helpers
  spid/              — SPID SP (SAML2 + XML-DSig, 9 IdPs)
  cie/ bundid/ franceconnect/ digid/ itsme/ eidas/  — EU eID connectors
  session/           — Redis session store
  audit/             — CloudEvents dispatcher + retention worker
  fga/               — Fine-Grained Authorization (OpenFGA-compatible)
  shield/            — Risk scoring engine
  gdpr/              — Art.30 RoPA + DSAR
  federation/        — OpenID Federation entity statements
  ssf/               — SSF / CAEP / RISC streams
  webhook/           — Async webhook fan-out
  scim/              — SCIM 2.0 server
  scimpush/          — SCIM Push to downstream apps
  forwardauth/       — Reverse proxy forward-auth
  worker/            — background jobs (PAM credential rotation, MDS3 sync)
frontend/            — Vite + React + Tailwind admin console
keys/                — RSA signing keys (gitignored)
```

---

## Ecosystem

Companion projects that build on the core server:

- **[clavex-operator](https://github.com/clavex-eu/clavex-operator)** — Kubernetes Operator for declarative, GitOps-managed IAM configuration (7 CRDs, continuous reconciliation).
- **[terraform-provider-clavex](https://registry.terraform.io/providers/clavex-eu/clavex/latest)** — Official Terraform provider ([source](https://github.com/clavex-eu/terraform-provider-clavex)).
- **[clavex-sdk-go](https://github.com/clavex-eu/clavex-sdk-go)** — Go SDK.
- **[clavex-sdk](https://github.com/clavex-eu/clavex-sdk)** — JS/TS SDK.
- **[clavex-examples](https://github.com/clavex-eu/clavex-examples)** — Starter kits and example integrations.

---

## Configuration

All config lives in `config.dev.yaml` (see `config.example.yaml`). Every key can be overridden via `CLAVEX_*` env var.

```yaml
http:
  addr: ":8080"
  base_domain: "localhost:8080"

database:
  url: "postgres://clavex:clavex@localhost:5432/clavex"

redis:
  addr: "localhost:6379"

auth:
  admin_secret: "change-me-in-production"
  access_token_ttl: 3600
  refresh_token_ttl: 2592000
  issuer_base: "http://localhost:8080"

keys:
  signing_key_path: "keys/signing.pem"
```

---

## Development

```bash
go test ./...                         # run tests
air                                   # hot reload (requires github.com/air-verse/air)
cd frontend && npm install && npm run build
make build                            # Go binary → bin/clavex

make migrate-up                       # apply all pending migrations
make migrate-down                     # roll back one migration
make migrate-status                   # show current state
```

---

## Deployment

### Docker Compose (recommended for staging)

```bash
docker compose up -d
```

### Docker (production)

```bash
docker build -t clavex:latest .
docker run -p 8080:8080 \
  -e CLAVEX_DATABASE_URL=postgres://... \
  -e CLAVEX_REDIS_ADDR=redis:6379 \
  -v ./keys:/app/keys \
  clavex:latest
```

### Kubernetes

A Helm chart is in `helm/clavex/`. For managed deployments contact [sales@clavex.eu](mailto:sales@clavex.eu).

---

## Service Status

Live uptime monitoring: **[status.clavex.eu](https://status.clavex.eu)**

Powered by [Upptime](https://upptime.js.org) — checks every 5 minutes, incidents tracked as GitHub Issues in [clavex-eu/upptime](https://github.com/clavex-eu/upptime).

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit your changes ([Conventional Commits](https://www.conventionalcommits.org/))
4. Open a pull request against `main`

---

## License

Clavex is licensed under the **[Business Source License 1.1](./LICENSE)** (BSL 1.1).

| Scenario | Commercial license required? |
|---|---|
| Local development, staging, CI | ❌ No — always free |
| Production with **1 organisation** | ❌ No |
| Production with **2+ organisations** | ✅ Yes |

Contact [sales@clavex.eu](mailto:sales@clavex.eu) or see [clavex.eu/pricing](https://clavex.eu/pricing).

BSL 1.1 includes an "Additional Use Grant Date": **4 years after each version's release date** the code becomes Apache 2.0 automatically.

---

## API Reference

The admin API is rooted at `/api/v1`. All endpoints require a Bearer token from `POST /api/v1/auth/login`.

### Tenant-scoped public endpoints (`/:org_slug/...`)

| Method | Path | Description |
|---|---|---|
| GET | `/:slug/.well-known/openid-configuration` | OIDC discovery |
| GET | `/:slug/.well-known/jwks.json` | Public JWK Set |
| POST | `/:slug/authorize` | Authorization endpoint |
| POST | `/:slug/token` | Token endpoint |
| POST | `/:slug/introspect` | Token introspection |
| POST | `/:slug/revoke` | Token revocation |
| GET/POST | `/:slug/userinfo` | UserInfo endpoint |
| GET | `/:slug/.well-known/openid-credential-issuer` | OID4VCI issuer metadata |
| POST | `/:slug/oid4vci/token` | Pre-authorized code token exchange |
| POST | `/:slug/oid4vci/credential` | Credential issuance (SD-JWT-VC) |
| POST | `/:slug/wallet/request` | Create OID4VP presentation request |
| GET | `/:slug/wallet/request/:id` | Fetch OID4VP request object |
| POST | `/:slug/wallet/response` | Submit OID4VP vp_token |

Full API documentation is available via the OpenAPI spec at `/api/v1/openapi.json`.

---

## Security

Please report vulnerabilities responsibly. See [SECURITY.md](SECURITY.md).

### Post-Quantum Readiness (production-grade primitives, roadmap-gated)

> Clavex ships production-grade NIST FIPS 204 (ML-DSA-65 / Dilithium3) signing
> primitives — sign/verify, automatic key bootstrap, encrypted key rotation, and
> hybrid JWKS discovery — with activation staged to the standards timeline. This
> follows the hybrid approach recommended by NIST SP 800-208 and BSI TR-02102-1:
> classical RSA signatures remain the primary trust anchor while PQC keys are
> discoverable via JWKS for PQC-aware clients.
>
> PQC signing of the primary OIDC tokens is intentionally gated on IANA JOSE
> algorithm registration (draft-ietf-cose-dilithium, in review) — signing today
> with a vendor-private identifier would break non-PQC-aware clients. Dual-signing
> lands once registration stabilises (~2026–2027).
>
> At the **transport layer** (FIPS 203 / ML-KEM), Clavex pins the hybrid
> `X25519MLKEM768` group as the preferred TLS 1.3 key exchange — live today.
>
> Enable discovery with `pqc_enabled: true` in config (requires `key_backend: db`).
> EU EUDI Wallet ARF mandates PQC readiness for credential issuers by 2030.
> See **[docs/PQC-ROADMAP.md](docs/PQC-ROADMAP.md)** for the full roadmap.
