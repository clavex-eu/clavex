# Post-Quantum Cryptography Roadmap

**Status: production-grade primitives, roadmap-gated activation.**

Clavex ships a complete, tested ML-DSA-65 (NIST FIPS 204) signing implementation
today. What is *deliberately* not switched on yet is PQC signing of the primary
OIDC/OAuth tokens — and that gate is an interoperability decision, not a
maturity gap. This document explains exactly what is implemented, why activation
is staged, and when each stage lands.

> **Why not just say "experimental"?** The word "experimental" implies the code
> is a prototype that might break or change shape. That is not the state here.
> The cryptographic primitives are production-grade and stable; only their
> *activation* on the main token path is gated on an external standards event
> (IANA JOSE registration). "Production-grade primitives, roadmap-gated
> activation" is the precise description.

---

## What is implemented today

| Capability | Status | Notes |
|---|---|---|
| ML-DSA-65 sign / verify | ✅ Done | NIST FIPS 204, security level 3 (≈ AES-192). Hedged (randomised) signing per FIPS 204 §3.4. |
| Automatic key bootstrap | ✅ Done | On first start with no active PQC key, a fresh ML-DSA-65 key pair is generated and persisted — no manual provisioning. |
| Encrypted key storage | ✅ Done | Private key stored in PostgreSQL, encrypted with AES-256-GCM under the same KEK as the classical signer (`key_backend: db`). |
| Key rotation | ✅ Done | `Rotate()` retires the active key and promotes a fresh one; retired keys persist through a grace period. |
| JWKS discovery (hybrid) | ✅ Done — **this release** | PQC public key is published in the JWKS endpoint alongside the classical RSA key, so PQC-aware clients can discover the capability. |
| Stable key IDs | ✅ Done | `kid` derived as SHA-256(pubkey)[:8], base64url — same scheme as the RSA signer. |
| **Dual-signing of OIDC tokens** | 🚧 Gated | Waiting on IANA JOSE algorithm registration (see below). |
| ML-KEM (FIPS 203) key encapsulation | 📋 Roadmap | Transport-layer complement; not yet wired. |
| SLH-DSA (FIPS 205) hash-based signatures | 📋 Roadmap | Conservative, no lattice assumptions. |

The signer is intentionally **passive**: it exposes the ML-DSA-65 public key for
discovery but does not yet sign the JWTs that clients validate. Classical RSA
remains the sole primary trust anchor.

---

## Why Clavex does not yet sign OIDC tokens with PQC

The blocker is **not** implementation readiness. It is standardisation:

- The IANA JOSE/JWT algorithm registry **has not yet assigned identifiers** for
  post-quantum signature algorithms.
- The relevant specification, **`draft-ietf-cose-dilithium`** (ML-DSA for
  COSE/JOSE), is still under active IETF review.
- Until that registration stabilises, any `alg` value used for PQC is a
  vendor-private placeholder. Clavex uses `CV-ML-DSA-65` (`CV` = Clavex Vendor)
  with JWK key type `MLWE`, following the current draft convention.

If Clavex signed production tokens with a vendor-private `alg` today, **every
OIDC/FAPI client that is not PQC-aware would fail to validate them** — because
the algorithm identifier would not resolve to anything in their JOSE library.
That breaks interoperability, which is the opposite of what an identity provider
exists to guarantee. Publishing the key for *discovery* costs nothing and breaks
nothing; signing with it prematurely breaks everyone.

---

## The hybrid migration pattern

Clavex follows the staged hybrid approach recommended by **NIST SP 800-208** and
**BSI TR-02102-1**. Each stage is a discrete, reversible step:

1. **Classical signature as primary trust anchor.** — ✅ **Done.** RSA (and EC)
   signatures secure every token. This never regresses during migration.
2. **Publish the PQC key in JWKS for discovery.** — ✅ **Done (this release).**
   PQC-aware clients can see the capability and prepare; nothing else changes.
3. **Issue dual-signed tokens** (classical + PQC) once the IANA registration is
   stable. — 🚧 **Gated. Estimated 2026–2027**, tracking
   `draft-ietf-cose-dilithium` progressing to an RFC. Dual-signing means legacy
   clients keep verifying the classical signature while PQC-aware clients can
   additionally verify the PQC one — no flag day.
4. **Deprecate classical signatures** once the PQC library ecosystem and client
   support mature. — 📋 **Estimated 2030–2035**, aligned with regulatory
   deadlines below.

The value of this ordering: at no point is a working integration broken to gain
quantum resistance. Each stage is additive until the very last.

---

## EU / regulatory timeline

Post-quantum migration in the EU is a decade-scale programme, and the early
years are exactly when *readiness* (not full activation) matters:

- **EUDI Wallet ARF 1.4 (§6.6)** mandates **PQC readiness for credential issuers
  by 2030**, aligned with the NIS2 / eIDAS 2.0 revision cycle.
- Broader EU and national roadmaps target **full PQC compliance in the
  2030–2035 window**, with harvest-now-decrypt-later exposure making *early*
  readiness meaningful well before the compliance deadline.

Clavex's staging is deliberately synchronised with this timeline: discovery
today, dual-signing as standards land mid-decade, classical deprecation as the
2030+ mandates take effect.

---

## TLS Transport Layer (FIPS 203 / ML-KEM)

Everything above concerns the **signature** layer (FIPS 204 / ML-DSA) — how tokens
are signed. That is a distinct, separate problem from the **transport** layer:
how the TLS connection carrying those tokens is key-exchanged. Clavex addresses
both, and they are at different maturity stages.

| | Signature layer | Transport layer |
|---|---|---|
| Standard | FIPS 204 — ML-DSA (Dilithium) | FIPS 203 — ML-KEM (Kyber) |
| Mechanism | Token/JWT signing | TLS 1.3 hybrid key exchange |
| Group | `CV-ML-DSA-65` (JWKS) | `X25519MLKEM768` |
| Status | Primitives ready, activation gated on IANA | **Live — pinned & test-verified** |

**Status: live.** `internal/crypto/tls.BuildServerTLSConfig` pins
`X25519MLKEM768` — a hybrid of classical X25519 and ML-KEM-768 (FIPS 203) — as
the preferred TLS 1.3 key-exchange mechanism, with classical X25519 and P-256 as
fallbacks:

```go
cfg.CurvePreferences = []tls.CurveID{
    tls.X25519MLKEM768,
    tls.X25519,
    tls.CurveP256,
}
```

Unlike the signature layer, the transport layer has **no interoperability
gate**: the hybrid group is already standardised (FIPS 203) and negotiated
transparently. A client that supports `X25519MLKEM768` gets post-quantum key
exchange; a client that does not falls back to classical X25519 automatically —
no client breaks either way. Go 1.24+ already includes the hybrid group in its
default preferences when `CurvePreferences` is nil; Clavex pins it **explicitly**
so the behaviour is stable and does not silently change with future Go defaults.
Verified by `internal/crypto/tls_test.go`, which negotiates a real handshake and
asserts `ConnectionState().CurveID == X25519MLKEM768`.

**When this applies — the TLS termination point matters.** PQC key exchange
protects the hop where Clavex terminates TLS directly. When a reverse proxy or
ingress terminates TLS in front of Clavex, the **client ↔ proxy** hop uses the
*proxy's* TLS stack, not Clavex's — so end-to-end PQC transport requires the
proxy to support it too. Two hard requirements at the edge:

1. **TLS 1.3 must be allowed.** `X25519MLKEM768` is a TLS 1.3-only group. A proxy
   capped at TLS 1.2 negotiates *no* post-quantum key exchange, regardless of
   Clavex's configuration.
2. **The proxy must be built with Go 1.24+** (or otherwise ship ML-KEM support)
   to offer the hybrid group.

### Traefik deployments

For the Traefik-fronted Helm deployment, PQC transport at the edge requires:

- **Traefik Proxy ≥ v3.5** — `X25519MLKEM768` was introduced in Traefik Proxy
  v3.5; earlier 3.x releases do not offer the hybrid group. Verify the **proxy**
  version actually running (`kubectl exec -it <traefik-pod> -- traefik version`,
  or the `appVersion` of the installed chart via `helm show chart traefik/traefik`)
  rather than trusting a Helm chart version number — the chart version changes far
  more often than the Traefik Proxy it bundles.
- A **TLS 1.3-capable `TLSOption`**. Note that a `TLSOption` pinning
  `maxVersion: VersionTLS12` disables PQC key exchange at the edge — the hybrid
  group cannot be negotiated below TLS 1.3. Ensure the ingress `TLSOption` allows
  TLS 1.3 for PQC-ready end-to-end transport.

See the [Helm chart README](../helm/clavex/README.md#post-quantum-tls-transport)
for the deployment-side recommendation.

## How to enable PQC discovery

PQC key management is opt-in:

```yaml
pqc_enabled: true      # generate/rotate the ML-DSA-65 key and publish it in JWKS
key_backend: db        # required — the PQC private key is stored encrypted in Postgres
```

With this set, Clavex bootstraps an ML-DSA-65 key on first start, stores it
encrypted, and merges its public JWK into the JWKS document. No token-path
behaviour changes: classical signatures remain primary.

---

## Summary

- The ML-DSA-65 **primitives are production-grade and done** — sign, verify,
  bootstrap, rotation, encrypted storage, JWKS discovery.
- PQC token **signing is gated on IANA JOSE standardisation**, not on Clavex
  implementation work.
- Activating PQC signing prematurely would **break interoperability** with every
  non-PQC-aware client — a staged hybrid rollout is the responsible path.
- The roadmap tracks the **EU 2030–2035 PQC timeline** stage by stage.

## References

- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- NIST FIPS 203 (ML-KEM) and FIPS 205 (SLH-DSA)
- NIST SP 800-208 — Stateful Hash-Based Signature Schemes / hybrid guidance
- BSI TR-02102-1 — Cryptographic Mechanisms: Recommendations and Key Lengths
- `draft-ietf-cose-dilithium` — ML-DSA for COSE/JOSE (IETF, in review)
- [EUDI Wallet Architecture and Reference Framework](https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/)
