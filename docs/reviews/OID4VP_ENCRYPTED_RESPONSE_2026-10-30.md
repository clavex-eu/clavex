# OID4VP encrypted responses for the Android wallet — 30 October 2026

## Trigger and scope

After reader CA rotation, the updated Android wallet rejected the request with
`haip profile requires an encrypted response mode ... got DirectPost`.
The verifier generated `direct_post` requests and could not receive encrypted
authorization responses. This was a missing capability, not a reason to relax
the wallet's HAIP validation or repeat the CA rotation.

Plain `direct_post` remains valid in the base OID4VP specification. For the
HAIP redirect profile, encrypted `direct_post.jwt` is required. The relevant
primary specifications are [OID4VP Final §8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.3)
and [HAIP Final §5](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html#section-5).
This change implements that response-encryption capability; it does not claim
complete HAIP certification, same-device session-binding compliance, ecosystem
registration or physical-wallet interoperability.

## Implementation

- New standalone `request_uri` requests default to `direct_post.jwt`. Signed
  request objects advertise one request-specific P-256 public encryption JWK,
  with `use=enc`, `alg=ECDH-ES` and a unique `kid`, plus both `A128GCM` and
  `A256GCM` in `encrypted_response_enc_values_supported`.
- Each request has a fresh random key, independent of JAR signing and other
  requests. The private key is encrypted with the deployment's existing
  secret-encryption key, in an authenticated envelope containing tenant and
  request identifiers. Concurrent fetches atomically retain the same key;
  replicas/restarts recover it from the database. No private JWK or ciphertext
  is serialized by the session APIs or client metadata.
- The response endpoint accepts compact JWE in the form-encoded `response`
  parameter. It restricts algorithms, curve and content encryption, rejects
  compression/critical extensions, bounds inputs to 2 MiB, and checks tenant,
  pending status, expiry and encrypted state. `kid` selects only a local stored
  session; no header-driven key discovery is performed.
- A request stored as encrypted cannot be completed with a plain `vp_token`.
  Mixed encrypted/plain outer parameters are rejected. Invalid encrypted envelopes
  do not consume a still-valid request. After decryption, issuer trust, holder
  binding, credential status, DCQL, account mapping and replay checks continue
  through the existing verification path.
- For mdoc, the Final redirect handover includes the RFC 7638 SHA-256 thumbprint
  of the recipient public key. A valid encrypted envelope cannot substitute a
  different recipient key in device authentication.
- Login challenges and CIBA requests use encrypted mode when the production
  handler's shared encryptor is configured. CIBA persists the same x509 client
  identifier that the JAR actually advertises; the account-binding checks remain
  mandatory after decryption.
- Success/failure erases the stored private-key ciphertext. The existing wallet
  worker clears bounded batches of expired keys, with an expiry partial index.
  Session results are retained; cleanup does not delete accounts or credentials.

## Compatibility and activation

Migration **192** adds `response_mode` and `response_key_ciphertext`. Existing
sessions retain `direct_post`; create a **new QR request** after deployment.
The current CA2 APK already supports encrypted responses and needs no new CA
or rebuild for this change.

An explicit `response_mode: "direct_post"` remains available for base-protocol
integrations. The legacy inline `wallet_authorization_endpoint` request path
keeps its existing default for conformance compatibility. Neither is advertised
as a HAIP request. The separate VCI presentation-required retry mechanism and
legacy wallet step-up endpoint are not converted by this change. `dc_api.jwt`
and a browser Digital Credentials API flow are not implemented here.

The deployment must apply migration 192 before starting the new backend. All
replicas must share the configured secret-encryption key. Rotating that master
key while requests are pending can invalidate them; this change does not rotate
the master key, JAR key, CA, licensing keys or application credentials.

## Validation evidence

Targeted race-enabled tests cover both GCM algorithms; private/public key
separation; concurrent fetches; another replica recovering the key; custom
caller state; replay; invalid ciphertext; wrong key/state/tenant; expiry;
plaintext downgrade; mixed parameters; encrypted errors; unsupported content
encryption; expired-key cleanup; matching/wrong mdoc recipient thumbprints; and
CIBA approval only for a credential bound to the requested account.

Migration 192 was tested down/up on a disposable PostgreSQL instance. The
private and public repositories use separate databases and Redis databases for
verification. Lint with the CI version (golangci-lint 2.12.1, Go 1.26.4) reports
zero issues in both repositories. Full race tests (`go test ./... -race -count=1 -timeout 10m`, Go 1.26.4)
passed: 49 packages in the private repository and 44 in the public repository,
zero failing packages. Handler packages completed in 170.661s and 149.050s
respectively. Deployment validation follows the private image build.

Public changes are applied as scoped patches adapted to its module namespace,
not by overwriting the private/public files wholesale. The public branch remains
local. No production payment, license or customer state is involved.
