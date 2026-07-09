# Clavex Features by Tier

This file is the authoritative, unambiguous list of which features are
**Community** (free, self-hosted, single organisation) and which are
**Business** or **Enterprise** (commercial license) for the purposes of the
"Additional Use Grant" in the [LICENSE](./LICENSE) file (Business Source
License 1.1).

If a feature is not listed here, it is Community.

The two Additional Use Grant conditions are independent:

1. **Single organisation** — production use serving more than one organisation
   requires a commercial license, regardless of which features are used.
2. **Community features only** — using any *Business* feature requires a
   commercial license, regardless of how many organisations are served.

---

## Community — free (Business Source License 1.1, single organisation)

Core authentication & protocols:

- OIDC / OAuth 2.0 Authorization Server
- SAML 2.0 (SP + IdP)
- SCIM 2.0 (inbound + outbound provisioning)
- Passkeys / WebAuthn, TOTP MFA
- OAuth 2.0 Device Authorization Grant (Device Flow)
- CIBA (Client-Initiated Backchannel Authentication)
- FAPI 2.0 & PAR

EU identity stack (Clavex EuroID):

- SPID, CIE, EU eID national integrations
- eIDAS 2.0 — OID4VCI / OID4VP / mdoc / HAIP
- Credential Chaining
- Anonymous Age Credential
- Selective Disclosure

Privileged access (base):

- Clavex PAM — JIT access, credential vault, Vault SSH CA

AI features:

- Audit Copilot
- Identity Advisor
- DCQL generator
- Regulatory Monitor

Security / analytics:

- Clavex Shield — threat intelligence & risk scoring
- Threat feed
- UEBA (User & Entity Behavior Analytics)
- Continuous Assurance

Agents & federation:

- MCP OAuth AS / Agent Tokens
- Federation Trust Anchor

Marketplace (consume / read):

- Browsing and reading the public Marketplace catalog
  (`GET /api/v1/marketplace/credentials`, `GET /api/v1/marketplace/credentials/:id`)
  — always public, no authentication required.

---

## Business — commercial license (any number of organisations)

Requires a valid Business or Enterprise license. A 30-day trial is available
(sales@clavex.eu or the Clavex license portal).

- WS-Federation IdP for SharePoint / ADFS
- Custom SaaS domains
- BYOK / per-organisation signing key
- Native SIEM sinks (Splunk HEC, Elastic ECS, Azure Sentinel)
- Clavex Marketplace **publishing** (create / update / delete your listings)
- Multi-organisation production use (also independently gated by condition 1)

---

## Enterprise — commercial license

Everything in Business, plus:

- Priority email & Slack support
- 72 h SLA on P0 / P1 issues
- Dedicated onboarding engineer
- Custom SAML / OIDC connector development
- Architecture review sessions
- Security advisory & CVE notifications
- Private binary releases & patch builds
- GDPR DPA (Data Processing Addendum) included

---

*Clavex Cloud (fully managed, hosted) is a separate product and is not governed
by the self-hosted Additional Use Grant above.*
