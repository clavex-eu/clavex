# Wallet status: remote lists, certificates and suspension

Implementation checkpoint: 29 October 2026. Local repository tests are evidence
of the implemented profile, not EUDI/IT-Wallet certification or a real-wallet run.
The JWT Token Status List wire profile remains pinned to
[draft-ietf-oauth-status-list-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html).
Certificate validation follows the complete, direct base-CRL subset of
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html).

## Remote signed lists

After credential signature, issuer trust and holder proof verification, tenant
`settings.wallet_status_sources` explicitly delegates a **public** JWKS to an
already trusted credential issuer/type and exact HTTPS status list URIs:

```json
{
  "wallet_status_sources": [{
    "format": "dc+sd-jwt",
    "credential_issuer": "https://issuer.example",
    "credential_type": "https://issuer.example/identity",
    "status_issuer": "https://status.example",
    "list_uris": ["https://status.example/list/1"],
    "jwks": {"keys": []},
    "max_age_seconds": 300,
    "cache_seconds": 60
  }]
}
```

Replace the empty example key set with authorised public RSA (2048+ bits) or
P-256 keys. Empty sets fail closed. Delegating a status signer does not trust
that party to issue credentials. Supported selectors also include `mso_mdoc`,
`key-attestation+jwt` and `wallet-attestation+jwt`. Key attestation type selector
is `key-attestation+jwt`; wallet/client attestation type selector is
`oauth-client-attestation+jwt`. These refer to distinct authenticated objects.
No remote `jku`, `x5u`, JWKS discovery or self-declared header key establishes trust.

The resolver checks the signed list subject/URI, issuer when present, type, algorithm,
signature, index, timestamps, declared TTL, decompression bounds and 1/2/4/8-bit
encoding. State zero is usable; revoked, suspended and unknown states are denied.
The base draft does not require `iss`, and `exp` is recommended. Missing expiry
remains bounded by the mandatory issued-at time and configured maximum age;
present expired/invalid timestamps are rejected. `require_issuer_claim:true` and
`require_expiration:true` let an ecosystem require both fields explicitly. A
present issuer must match the configured status issuer. The authorised signing
key and exact URI always remain mandatory, even when `iss` is absent.
Failure to obtain sufficiently fresh evidence returns a temporary-unavailability
result, never an implicit active state. Invalid evidence is rejected.

Cache entries are separated by tenant, complete signer policy and exact URI.
The default reuse window is 60 seconds (maximum configurable 300), clipped by
signed expiry/TTL when present, maximum age and HTTP freshness. Maximum age defaults to 300
seconds (maximum configurable 3600). No stale-on-error fallback. `no-store` and
`no-cache` disable reuse; HTTP `Age` cannot extend freshness. Revocation can be
observed after the bounded reuse interval, not instantaneously on other nodes.
The shared cache is bounded to 128 entries/16 MiB and deduplicates concurrent
requests, with at most 32 in-flight requests and four per tenant.

Requests send no credential, patient identifier, status index, authentication
header or cookie. Only the list URI is retrieved. Network controls reject
private, loopback, link-local and special-use addresses after DNS resolution at
socket creation, including IPv4-mapped and transition ranges. No proxy,
redirects or response compression. HTTPS JWT fetches require TLS 1.2+, three-
second deadlines and bounded headers/bodies. Global webhook private-address
exceptions do not disable these controls. Trusted Go test dependency injection
is not configurable through tenant settings or HTTP parameters.

## mdoc and certificate state

Verification retains the **verified** certificate path and checks each non-root
certificate against its actual issuer's CRL. Root trust is rechecked and locked
against concurrent deletion/deactivation before the authentication decision.
`wallet_certificate_distrust` accepts SHA-256 fingerprints of DER certificates;
a matching certificate anywhere on the verified path is denied.

The issuer-specific `wallet_crl_sources` override is optional:

```json
{
  "wallet_crl_sources": [{
    "issuer_sha256": "<64 lowercase hex characters for actual issuer certificate>",
    "uri": "https://ca.example/base.crl",
    "max_age_seconds": 86400,
    "cache_seconds": 60
  }]
}
```

Without an override, the first CRL distribution point in the signed certificate
is used. HTTP distribution points are accepted because the CRL signature is
verified against the actual issuer; the same SSRF, redirect, size and timeout
controls apply. DER or a single PEM X509 CRL is accepted. Every non-root
certificate needs fresh, correctly signed evidence when required. CRL maximum
age defaults to one day, configurable up to seven days; `nextUpdate` and HTTP
freshness remain upper bounds. Complete direct CRLs only: OCSP, delta/indirect/
partitioned CRLs and unsupported critical extensions are not implemented and
must not be described as covered. A declared unsupported mechanism never
silently becomes a positive status decision.

Authentication/deferred delivery require certificate revocation evidence by
default. Explicit development/compatibility policy
`wallet_certificate_revocation_required:false` allows **absent** CRL references,
recording `missing_permitted`; it never ignores a declared bad or revoked CRL.
Certificate status remains separate from credential-list status. The existing
`wallet_status_required:false` exception does not implicitly disable certificate
checks. Standalone diagnostic verification can permit missing status, while
still reporting the exception; authentication must not infer assurance from it.

For mdoc credential lists, the parser reads a signed MSO `status_list` extension
or `status.status_list`, rejecting ambiguous/unsupported combinations. New local
issuance uses `MSO.status_list`. These are explicit extension layouts, **not a
claim of universal ISO or IT-Wallet interoperability**. Each issued record stores
the stable COSE signature-input/signature digest so selective disclosure does not
change its status identity. Local status references must match the tenant,
issued record, document type and allocated slot. Deferred delivery checks the
actual signed MSO expiry and certificate path without demanding a presentation
DeviceAuthentication that cannot exist before delivery.

The direct proximity endpoint applies the same status/certificate policy and
commits completion in the transaction holding the corresponding trust/state
locks. Proximity here is the existing HTTP transport; no new claim about NFC/BLE
ISO transport conformance is made.

## Attestations

Authenticated key attestations and wallet/client attestations with a declared
status reference are checked through an explicit matching delegation before
issuance/client authentication. `key_attestation_status_required` and
`wallet_attestation_status_required` can require a reference; defaults preserve
profiles that do not declare one. An invalid declaration is always rejected.
A key attestation without `iss` can be authenticated only against one unambiguous
configured trusted signer (at most 20 candidates); header keys never establish
trust. `key_attestation_issuer_required:true` can require the issuer claim for a
stricter ecosystem. This follows OID4VCI Final Appendix D.1 rather than making
a legacy issuer-claim requirement universal.

Migration **189** persists the minimal authenticated parent status pointers for
issued credentials and pending deferred requests. Credential authentication and
delivery recheck those pointers. A bounded background monitor (30-second ticks,
oldest-first batches of 64) propagates a known parent revocation permanently to
child records and published lists. A suspended parent temporarily suspends its
children; recovery clears only a suspension introduced by this monitor, never
an independent manual hold. Unknown/unavailable evidence does not manufacture
a revocation or restore a child; synchronous decisions remain denied. Previously
issued records without authenticated parent links are not retrospectively linked.

Key attestation pointers are captured after proof validation. Wallet/client
attestation pointers are captured by the confidential-wallet token-grant
integration described in [authorization-code and confidential clients](wallet-authorization-code.md). Ecosystem trust-list/x5c onboarding and other
national requirements remain separate; these mechanisms do not by themselves
establish complete IT-Wallet conformance.

## Local state transitions and migration

Migration **188** adds list bit width, suspension state and the stable mdoc COSE
digest. Existing one-bit lists keep their encoding; new lists use two bits. A
first suspension upgrades a one-bit list atomically, preserving all old states
and indices. Published list JWTs advertise the actual width. No historical
credential receives an invented status pointer.

Administrative operations, scoped to the organisation:

- `POST .../oid4vci/issued/:cred_id/suspend`: active tracked credential → suspended.
- `POST .../oid4vci/issued/:cred_id/restore`: suspended → active.
- `POST .../oid4vci/issued/:cred_id/revoke`: active/suspended → permanently revoked.

Restoring a revoked credential now returns **409**; reissue instead. Historical
untracked credentials can be revoked but cannot be suspended because the
suspension would not be observable through a signed reference. Registry and list
changes commit together. Delivery and authentication reject suspended records.
The admin page distinguishes suspension and removes restore for revoked records.
Migration rollback refuses to narrow an already used multibit list or discard
new state; a data rollback requires explicit review.

## Remaining integration boundaries

Pin the actual wallet/app, EUDI/national profile, status-list version, metadata,
trust anchors and certificate lifecycle before external acceptance tests. A test
root installed manually in an app does not establish ecosystem trust. IT-Wallet
x5c/trust-list requirements and OCSP/delta CRL requirements are not satisfied
merely by these mechanisms. ISO mdoc CWT status lists and identifier lists are
not implemented by the JWT MSO extension above. Authorization-code/deferred,
confidential clients and multi-credential DCQL are implemented separately;
see [the current verification report](reviews/WALLET_VERIFICATION_2026-10-29.md)
for external-suite outcomes and remaining acceptance work.
