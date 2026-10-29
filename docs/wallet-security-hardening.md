# Wallet issuer and verifier hardening — 28 October 2026

This follow-up covers mdoc verification, pinned key-attestation trust, credential
authorization and transactional issuance. It builds on the proof checks and
deferred holder-key storage described in [proof validation](oid4vci-proof-validation.md).
It is not a declaration of full OpenID, HAIP, EUDI Wallet or eIDAS conformity.

## mdoc verification

Both the DCQL verifier and the legacy proximity response endpoint require issuer
trust and device authentication. They load active IACA roots for the session's
organization and document type. An empty `doc_types` list permits all document
types for that explicitly trusted root; otherwise the requested type must be
listed. Missing roots or a root-storage error cannot enable a trust bypass.
Supplied intermediate certificates are used only to construct a chain to those
roots, and do not become trust anchors themselves.

The verifier checks the issuer signature, certificate validity, MSO validity and
type, disclosed-item digests, device key, and detached device signature. Device
authentication uses the Final OID4VP redirect handover and reconstructs the
DeviceAuthenticationBytes payload; external AAD is empty. The expected client ID,
nonce and response URI come from the stored request, not from the response.
The encrypted-key variant of the transcript builder is tested against the
published Final specification vector, but this does not implement encrypted VP
responses or the Digital Credentials API profile.

DCQL mdoc currently supports one query, one presentation and one document. It
checks the query ID, document type, required namespace/element paths and supported
claim-set alternatives. Unsupported multiple-document/set/bearer queries are
rejected. Attributes are mapped from the document's primary namespace, preserving
verified namespace data separately. Failed documents are not silently omitted
from an otherwise accepted response. Session completion uses a conditional update
so a repeated response cannot complete the same session twice.

Verifier metadata now advertises implemented formats, Final mdoc COSE algorithm
parameters and supported SD-JWT holder algorithms. Unsupported generic JWT VC/VP
formats were removed. The RP federation metadata retains its legacy `vp_formats`
field separately from Final `vp_formats_supported`. The proximity request API
still includes legacy Presentation Exchange fields; it is not fully migrated to
a Final request profile merely because its response verification is hardened.

## Key-attestation trust

An organization must explicitly pin attesters in its existing administrative
`settings` object. Example shape (replace the example issuer and public JWK):

```json
{
  "credential_key_attesters": [
    {
      "issuer": "https://wallet-provider.example",
      "jwks": { "keys": [{ "kty": "EC", "crv": "P-256", "kid": "<key id>", "x": "<public x>", "y": "<public y>" }] }
    }
  ]
}
```

This is an administrator-managed trust configuration, not a registration endpoint
available to wallets. EC pins must be P-256 and RSA pins at least 2048 bits. No
remote key URL is fetched from the proof or attestation. A header JWK or x5c does
not establish attester trust. The signature must verify against a pin belonging
to the attested `iss`, with a matching configured `kid` when one is supplied.

When `require_key_attestation` is enabled, missing attestations are rejected.
Provided attestations are checked even when optional: protected type/algorithm,
issuer trust, temporal validity, expiration, nonce and inclusion of the verified
holder key in public `attested_keys` are required. The issuer metadata advertises
the configured pins rather than substituting its own signing key. Required
attestation with no configured trust fails closed, including metadata retrieval.

These checks authenticate the attester and the attested holder key. They do not
independently prove secure-hardware certification or a biometric assurance level.
Advanced resistance policies, attestation status mechanisms and ecosystem trust
registries need profile-specific implementation. Removing a pin stops subsequent
initial requests; deferred requests currently retain the holder key authenticated
at creation rather than a complete revocable attestation-evidence record.

## Credential authorization and token bindings

An authorization-code access token needs the exact credential scope advertised
for the selected configuration or a matching `openid_credential` RAR grant.
Credential RAR grants take precedence over generic credential scopes. Restricted
dataset identifiers are not treated as unrestricted configuration grants;
`credential_identifier` selection is explicitly rejected until dataset mapping
is implemented. Pre-authorized requests also check their selected configuration
against the offer. User lookup and offer creation enforce the user's tenant and
eligibility; deleted/disabled/foreign subjects cannot downgrade into org-level
issuance during deferred approval.

Access JWTs require a trustworthy lifetime. Bearer tokens longer than five minutes
are rejected; DPoP-bound tokens must pass the existing possession checks, and
certificate-bound tokens require the matching peer certificate on the actual TLS
connection. Arbitrary forwarded certificate headers are not accepted as proof.
Deployments terminating client TLS at a proxy need an explicitly designed trusted
transport integration; sending a header alone does not enable this path.

Wallet clients must obtain suitable token lifetimes or sender-constrained tokens;
the generic IAM token lifetime is not changed globally by this work.

## Atomicity and failure behavior

Issuance repositories accept a transaction-backed Querier. Each issuance request
uses a local handler copy bound to that transaction, including mdoc signer lookup.
The pool and handler shared by other requests are not mutated. Offer/deferred row
locks and state rechecks serialize competing requests across application nodes.
The pre-authorized code is exchanged through a conditional, single-use update.

Credential records, offer consumption, deferred creation/completion and linked VP
completion are committed together. Every proof is validated before signing; a
failed item aborts the entire batch, including the legacy batch endpoint. Response
serialization/encryption occurs before commit, and credential bytes are returned
only after a successful commit. A test that fails the second database insertion
verifies rollback of the first insertion and preservation of the pending offer.

This is not a distributed transaction with Redis, external webhooks, an HSM or
the network response. A consumed nonce stays consumed after a database rollback;
retry with a fresh nonce/proof. External calls can occur again on retry. An
ambiguous commit/network outcome is not an exactly-once delivery guarantee.

The generic login authorization engine and PostgreSQL tenant RLS are not changed
by this limited transaction interface refactoring.

## Migration and rollout

1. Apply migration **183** for deferred holder keys and **184** for opaque access
   token expiry before starting this server build.
2. Configure IACA roots/document-type policies and, where required, attester pins.
   Do not import a certificate merely because a wallet sends it.
3. Request fresh opaque tokens. Migration 184 leaves existing token issue times
   unknown; old NULL-expiry tokens are rejected instead of assigning them an
   invented issue time. New opaque tokens expire after five minutes as advertised.
4. Keep the separate credential-CA replacement from the earlier patch in mind:
   update test trust anchors and reissue test credentials where necessary.
5. Rerun the role-specific OpenID plans with explicitly configured test trust, then
   test actual wallets using their applicable verifier/issuer trust framework.

**Deferred update — 29 October:** pre-authorized deferred issuance now has a
separate rotating refresh grant, capped at seven days, with access tokens capped
at five minutes. See [deferred refresh](wallet-deferred-refresh.md) for lifecycle,
migration 186, delivery/retry semantics and supported client profiles. Existing
legacy bearer offers are not backfilled with refresh rights. Authorization-code
configurations requiring deferred issuance or VP chaining remain rejected; legacy
batch configurations requiring deferred issuance or VP chaining are rejected.

There are distinct trust directions: the wallet's trust in the verifier/JAR or
issuer, Clavex's trust in credential IACA roots, and Clavex's trust in wallet key
attesters. Registering test certificates in a modified wallet is useful lab setup;
it does not establish official recognition in an EUDI ecosystem. Generic browser
TLS trust does not automatically establish all these relationships.

## Validation and remaining gates

Tests include the official handover vector, a certificate chain with an
intermediate, trusted issuer plus independently constructed device proof,
cross-session negatives, HTTP verifier query/root policy, attester substitution,
wrong holder/nonce/expiry, credential scopes/RAR, token bindings, concurrent
offer/token/deferred use, batch rollback, tenant binding and a one-connection pool.
They run against isolated PostgreSQL 17 and Redis 7 services when the test
environment variables are set. See the review report for command outcomes.

Still open: full external conformance rerun, real IT-Wallet/EUDI interoperability,
remote credential/attestation status and revocation checking, plus mdoc/certificate
revocation, multiple-credential DCQL, additional transport/profile support, and the
additional deferred client profiles described above. The 29 October account
binding checkpoint now enforces signed local subjects or explicitly registered
external identities for CIBA and fixes the separate local wallet step-up path;
see [wallet account binding](wallet-account-binding.md). Actual external identity
profile selection and administrative identity review remain deployment duties.
These limitations must remain visible in any readiness assessment. No cluster deployment or commercial
state change is part of this work.

Validation results for the 28 October hardening checkpoint (before account binding):

- Private main module: `go test ./... -race -timeout 5m` passed, 49 packages,
  with PostgreSQL/Redis integration configured; includes cached unaffected tests.
- Public main module: selected `TestVCI|TestMdoc|TestFinal` tests passed with
  `-race -count=1` in handler, mdoc and oid4w, using real isolated services.
- `go vet` on handler/repository/mdoc/oid4w passed in both modules. Public server
  and migrate commands built successfully.
- Migration 184 applied on PostgreSQL 17; down/up SQL also passed inside a
  rolled-back transaction. Neither migration was applied to the maintainer's cluster.
- The external OpenID suite and real wallet apps have not been rerun. Earlier
  conformance reports are historical results, not evidence for this changed build.


### Account binding checkpoint — 29 October 2026

- Private: `go test ./... -race -timeout 5m` passed, 49 packages with tests;
  includes cached unaffected tests. PostgreSQL 17 / Redis 7 integration enabled.
- Public: `go test ./internal/handler ./internal/oid4w ./internal/repository
  ./internal/mdoc ./internal/session -race -timeout 5m` passed (five packages),
  with the same isolated test services. This is not a full public-module test run.
- Additional administrative-review and configured-profile rejection cases were
  added afterward; the affected external-link test passed again in both modules
  with `-race -count=1`.
- `go vet` on handler/repository/oid4w/session and builds of server/migrate passed
  in both modules. `make openapi-check` and `git diff --check` passed in both.
- Migration 185 applied to the isolated database. Down/up SQL passed inside a
  rolled-back transaction. No maintainer-cluster migration was applied.
- The external OpenID suite and real-wallet apps were not rerun. No formal
  certification or official EUDI trust recognition is inferred.

See [account binding](wallet-account-binding.md) for the new profile, manual
administration endpoints, privacy limitations and remaining integration duties.


### Deferred refresh checkpoint — 29 October 2026

- Private main module: `go test ./... -race -timeout 5m` passed, 49 packages
  with tests, including cached unaffected packages. Real isolated PostgreSQL 17
  and Redis 7 were configured.
- Public: handler/oid4w/repository/mdoc/session tests passed with `-race` (five
  packages). This is not a full public-module test run.
- Following the final storage-error classification changes, all handler tests
  passed again in both modules with `-race -count=1 -timeout 5m`.
- `go vet` on handler/repository/oidc, server/migrate builds, OpenAPI coverage and
  `git diff --check` passed in both modules. Code graphs were updated using AST
  extraction; optional SQL/Terraform parsers remain unavailable.
- Migration 186 applied on a fresh isolated database. Down/up SQL passed inside
  a rolled-back transaction in a separate test database. Assertions confirmed
  that downgrade invalidates new-generation access hashes and preserves legacy
  hashes. No cluster migration was applied.
- The OpenID external suite and real IT-Wallet/EUDI apps have not been rerun.

See [deferred refresh](wallet-deferred-refresh.md) for the seven-day grant limit,
rotation/reuse policy, migration preflight and lost-response recovery limitations.


### Local SD-JWT status checkpoint — 29 October 2026

See [local credential status](wallet-status-local.md) for migration 187, the
strict default for authentication and the explicit compatibility exception.
New HTTP SD-JWT issuance now binds a signed status pointer to an issued record.
Local revocation is enforced before CIBA/step-up approval and deferred delivery.
This is block 3A: remote status retrieval/cache, mdoc/certificate status and
attestation revocation remain open. The external suite and real wallets have not
been rerun. The authorization-code/deferred and confidential-wallet-client gaps
remain explicit follow-up work; they are not restrictions imposed by OID4VCI.


Validation for block 3A:

- Private main module: `go test ./... -race -timeout 5m` passed (49 packages
  with tests, including cached unaffected packages), with isolated PostgreSQL 17
  and Redis 7 enabled.
- Public: handler/oid4w/repository/mdoc/session passed with `-race` (five packages;
  not a full public-module test run).
- `go vet` on handler/repository/oid4w, builds of server/migrate, OpenAPI coverage
  and `git diff --check` passed in both modules. AST graphs were updated.
- Migration 187 applied to the isolated database. Down/up SQL and independent
  assertions rejecting cross-tenant list pointers, duplicate slots and invalid
  indices passed in a rolled-back transaction. No cluster migration was applied.
- External OpenID plans and real wallets were not rerun. Passing these tests does
  not close remote, mdoc/certificate or attestation revocation integration.
