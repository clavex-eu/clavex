> Updated checkpoint: see [remote status, mdoc and suspension](wallet-status-remote.md) for migrations 188–189 and the current state transitions. The binary/local-only limitations below describe checkpoint 3A.

# Credential status: local SD-JWT checkpoint

29 October 2026. This is **block 3A**, not completion of every status/revocation
profile. Changes are local in the private/public worktrees, not deployed.

## Findings and implemented path

Previously, status lists and administrative revocation existed, but HTTP SD-JWT
issuance did not allocate/bind a status slot or embed its reference. A verifier
did not consult status before approving a presentation. The old offline helper
also did not bind the JWT subject to the requested list, check `bits`, or limit
decompression; it could panic on a short decoded list. List publication put the
type in `cty`, used a UUID rather than the list URI as `sub`, and did not enforce
the route tenant. Revoke/restore handlers likewise lacked an explicit
credential-versus-route tenant check. These paths are corrected in this increment.

Each new HTTP-issued SD-JWT now receives a distinct local list slot. The signed,
non-disclosable `status.status_list` contains its HTTPS URI and integer index.
Allocation, signing, issued-record creation and issuance authorization consumption
share the existing transaction. An organisation-scoped transaction advisory lock
serializes list creation/rollover. Failed issuance rolls back the allocation.
The underlying stateless issuance helpers accept an optional caller-supplied
status reference; they cannot allocate a database slot on their own.

The database records the SHA-256 of the **issuer JWT**, in addition to the existing
hash of the full issued credential. The issuer JWT remains identical when the
holder changes disclosures or key-binding proofs. Local checks match tenant,
signed list/index, VCT and issuer-JWT digest to a non-revoked issued record and an
actually allocated slot. A missing record is unknown, not active. No identity
is inferred from an arbitrary presentation serialization hash.

For local status decisions, PostgreSQL is the authoritative distribution channel;
the verifier does not fetch its own HTTP endpoint or cache active results. SHARE
locks order decisions against concurrent revocation/restore. A revocation committed
before that decision blocks it; a completed earlier authentication is not
retroactively cancelled. Database record expiry and signed credential expiry
remain independent of a valid status bit.

Controls run in CIBA approval, wallet step-up, issuance requiring a VP, standalone
presentation completion, administrative batch verification and deferred delivery.
Deferred delivery also rejects a locally revoked/expired issued record before
consuming the transaction. SD-JWT delivery verifies the actual signature/expiry,
even if legacy maintenance has extended only the database expiry field.

## Policy and compatibility

**CIBA, wallet step-up, VP-required issuance and SD-JWT deferred delivery require
status by default.** Standalone/diagnostic presentation verification permits a
missing reference by default, but checks a supplied reference. Organisation
settings may explicitly set:

```json
{"wallet_status_required": false}
```

This is a compatibility exception for missing status, not evidence of an active
credential. Setting the value to `true` also requires status in standalone checks.
A value of another type is a configuration error and does not permit approval.
The policy is re-read under the decision transaction's organisation lock.

A malformed, disclosed-only, unknown or unresolvable **declared SD-JWT status** is
not bypassed by the compatibility exception. Newly emitted status references are
always in the issuer JWT; payload/mapping overrides of the reserved status claim
are rejected. CIBA stores a server-derived `_clavex_credential_status` assessment:
`valid_local` or `missing_permitted`, separate from account-binding evidence.
Neither string establishes an assurance level, eIDAS certification or EHDS compliance.

No setting or historical record is automatically changed to enable compatibility.
Existing credentials without status may need reissuance or an explicit reviewed
compatibility policy. Permitting missing status can also permit omission of a
selectively disclosed external reference; sensitive profiles should require an
always-available status reference instead.

## Public list and strict offline validation

`GET /{org_slug}/oid4vci/status-list/{list_id}` serves
`application/statuslist+jwt`, with protected `typ=statuslist+jwt`, `sub` equal to
the exact list URI, `iat`, a five-minute `exp` and `ttl=60`. HTTP caching is capped
at 60 seconds. The endpoint uses the signer abstraction and rejects a list owned
by another tenant. Local publication remains a **one-bit** active/invalid list;
no new suspension endpoint is introduced. Existing administrative restore remains
an explicit local policy action.

The offline validator is pinned to
[draft-ietf-oauth-status-list-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html).
The [Datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
listed it in the RFC Editor queue at review time; this document assigns no RFC
number and makes no W3C StatusList2021 compatibility claim.

The selected JWT profile checks an explicitly supplied trusted key, protected
type/algorithm, exact subject URI, optional expected issuer, required issue/expiry
times, future clock skew and bounded freshness/TTL. It reads 1/2/4/8-bit packed
lists: zero is valid; one is invalid/revoked; two is suspended; unrecognized values
and out-of-range indices are unknown. Local lists must have the expected fixed
size. External-format validation caps token, encoded and decompressed sizes and
rejects invalid compression. A zero-length/short list does not panic.

These are profile restrictions, not a claim to accept every permitted encoding,
algorithm, status mechanism or URI scheme in the draft. `CheckStatus` remains an
offline helper; successful signature checks alone are not a status decision.

## Deliberate boundaries and remaining increments

**No remote status URI is fetched in this increment.** The runtime resolver accepts
only a credential verified with the local issuer key and an exact same-tenant
canonical list URI backed by local records. A well-formed nonlocal reference
returns unavailable (503 in authentication flows), preserving pending state; an
invalid/revoked/missing-required reference is rejected. It cannot approve using
an old cached result or discover trust from a key in the wallet's JWT headers.

Remaining block 3 work:

- Remote TSL retrieval and explicit status-signer authorization, with SSRF/DNS/
  redirect controls, response limits, bounded concurrency and tenant/trust-scoped
  cache freshness. These protections are not implemented by merely having an
  offline validator. Real external wallets declaring remote status may remain
  unusable until this profile is configured and implemented.
- mdoc/CWT status mechanisms and DS/IACA certificate revocation (CRL/OCSP or the
  actual selected ecosystem mechanism); certificate-chain trust is not revocation.
  The local mdoc deferred-delivery guard only checks its database issuance record.
- Wallet/key-attestation lifecycle and revocation, distinct from credential status.
- Local suspension policy/endpoints if required; one-bit issuance cannot express
  a distinct suspended state. No verifier propagation claim for it is made here.

mdoc authentication without supported status is denied under the strict default;
allowing missing status through compatibility does not establish mdoc/certificate
revocation checking. No new metadata advertises these missing profiles.

## Migration and verification

Migration **187**, after 183–186, adds the issuer-JWT digest and uniqueness,
tenant-FK and index-range constraints. No reference/digest is invented for
historical credentials and no credential is automatically revoked or reissued.
Existing duplicate slots, cross-tenant list pointers or invalid indices require
manual review; the migration fails rather than deleting or silently merging them.
Down/up removes/recreates the digest column without reconstructing old digests;
rollback therefore requires review/reissuance before relying on this binding again.
Do not deploy an older verifier as though it retained these checks.

Status URIs/indices and credential digests remain correlatable references, not
anonymized data. Retention, disclosure and access policies still apply, including
for age credentials. This work does not claim privacy or regulatory compliance.

Regression coverage includes signed reference publication, CIBA before/after
revoke/restore with different disclosure sets, step-up revocation, deferred denial,
tenant separation, concurrent slot allocation and rollover, type/key/URI/issuer/
time/bit-width negatives, unknown values, malformed references, decompression
limits, and absent-status policy. Older account-binding tests explicitly opt into
missing-status compatibility so they still test that separate control.

The OpenID external suite and actual IT-Wallet/EUDI apps have not been rerun.
Local test results are recorded in [wallet hardening](wallet-security-hardening.md).
