# ID-JAG Roadmap

**Status: RFC 7523 JWT Bearer grant implemented and stable. ID-JAG itself is roadmap-gated.**

Clavex ships a complete, tested implementation of the **RFC 7523 JWT Bearer
authorization grant** (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`)
today. What is *not* implemented is **ID-JAG**
(`draft-ietf-oauth-identity-assertion-authz-grant`), a specific profile built
on top of RFC 7523 + RFC 8693 for cross-domain identity federation between
agentic/AI systems. This document explains the distinction, why activation of
the ID-JAG profile is staged, and what changes when it lands.

---

## The two layers

### Layer 1 — RFC 7523 JWT Bearer grant (implemented today)

The generic, standards-track mechanism defined by RFC 7523 §2.1/§3/§4: a
caller presents a JWT (`assertion`) signed by an issuer the org has
explicitly configured as trusted, and the token endpoint verifies it and
issues a Clavex access token for the subject the JWT asserts.

| Capability | Status |
|---|---|
| `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` at the token endpoint | ✅ Done |
| Per-org trusted issuer configuration (`jwt_bearer_trusted_issuers` table) | ✅ Done |
| Signature verification (inline JWKS or `jwks_uri`) | ✅ Done |
| Standard claim validation: `iss`, `sub`, `aud` (must match the token endpoint), `exp`, `nbf`/`iat` with clock-skew tolerance | ✅ Done |
| JTI replay prevention | ✅ Done |
| Configurable claim mapping (external assertion claim → Clavex access-token claim) | ✅ Done |
| Per-issuer scope restriction | ✅ Done |
| Admin CRUD for trusted issuers (`/api/v1/organizations/:org_id/jwt-bearer-trusted-issuers`) | ✅ Done |

This is a **general-purpose cross-domain federation primitive**, useful on its
own: any system that can mint a signed JWT with the right claims and has been
registered as a trusted issuer for an org can obtain a Clavex-scoped access
token for a subject. It is not tied to any particular client, agent framework,
or draft specification.

Implementation: `internal/oidc/jwt_bearer.go` (`ValidateJWTBearerGrant`),
`internal/handler/jwt_bearer.go` (`jwtBearerGrant`),
`internal/repository/jwt_bearer_trusted_issuers.go`.

### Layer 2 — ID-JAG (not implemented, roadmap-gated)

**ID-JAG** (`draft-ietf-oauth-identity-assertion-authz-grant`, currently
**draft-03**) is a specific *profile* that layers additional semantics on top
of RFC 7523 and RFC 8693:

- A well-defined issuance flow where an OP mints an "Identity Assertion
  Authorization Grant" JWT for a *resource party* on behalf of an
  authenticated user, intended to be redeemed at a *different* domain's token
  endpoint.
- Draft-specific claims and constraints on top of the generic `assertion`
  (e.g. binding to a specific resource/audience pattern for the receiving
  domain, intended primarily for AI-agent-to-agent and cross-tenant identity
  propagation scenarios).
- An expectation that the receiving AS treats the JAG as a first-class
  RFC 7523 grant, i.e. it is designed to be *redeemable* through exactly the
  generic mechanism Clavex already implements.

None of this is implemented. Clavex's `ValidateJWTBearerGrant` and the
`jwt_bearer_trusted_issuers` table intentionally know nothing about ID-JAG's
specific claim vocabulary or issuance flow — only generic RFC 7523.

## Why ID-JAG is not implemented yet

The blocker is standardisation maturity, not implementation readiness:

- The draft is at **draft-03** and still under active IETF OAuth WG
  discussion; claim names, audience-binding rules, and issuance semantics can
  still change incompatibly between draft revisions.
- Interop support is immature industry-wide: as of this writing even
  **Keycloak's** ID-JAG support is partial — it implements the **receiver**
  side only (redeeming a JAG at the token endpoint), not the **issuer** side
  (minting a JAG on behalf of an authenticated user for another domain).
  Building the issuer side of a profile that isn't stable elsewhere risks
  building against claim semantics that change before the draft freezes.
- Hard-coding a specific draft revision's claims into the core token-issuance
  path would mean either breaking changes on every draft revision, or carrying
  parallel legacy code paths — the same interoperability trade-off documented
  in `docs/PQC-ROADMAP.md` for post-quantum signing.

## What activation will look like when the draft stabilises

Because Clavex already has the generic RFC 7523 building block in place,
activating ID-JAG support is expected to be a **thin additive layer**, not a
rewrite:

1. Add ID-JAG-specific claim validation (audience binding, any mandatory
   claims defined by the frozen spec) as an opt-in layer on top of
   `ValidateJWTBearerGrant` — the signature verification, trusted-issuer
   lookup, replay prevention, and token issuance path do not change.
2. Add an **issuer** side: an endpoint/flow that mints an ID-JAG-shaped JWT on
   behalf of an authenticated Clavex user, scoped to a target resource party's
   domain — this is new work, since RFC 7523 alone only covers the *receiver*
   side.
3. Update discovery metadata to advertise ID-JAG support once both sides are
   implemented and conformance-tested.

No changes are anticipated to the `jwt_bearer_trusted_issuers` schema or the
core grant-handling code path in `internal/handler/jwt_bearer.go`.
