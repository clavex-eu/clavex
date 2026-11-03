# OID4VCI proof validation and deferred holder keys

Implementation notes, 28 October 2026. Scope: credential issuance proofs and the
existing offer-based deferred issuance path. This is not a declaration of full
OID4VCI, HAIP, EUDI Wallet or eIDAS conformity.

## Accepted proofs

The Final `proofs.jwt` array and the legacy singular `proof` object use the same
validator in the pre-authorized, authorization-code and legacy batch endpoints.
Supplying both forms, an empty array, an empty/duplicate proof, or more than 100
proofs is rejected. The legacy batch endpoint accepts one proof per item.

Every proof is checked before issuance begins:

- Compact signed JWT with protected `typ=openid4vci-proof+jwt`.
- ES256/P-256, PS256 or RS256 with RSA keys of at least 2048 bits. The mdoc
  configuration accepts only ES256, matching its advertised proof algorithms.
- A public asymmetric `jwk`, or an `x5c` leaf containing the holder's public key;
  signature verification always runs. Private/symmetric keys and ambiguous key
  references are rejected. Unsupported DID/attestation `kid` resolution is
  rejected explicitly, rather than accepting a proof without verifying it.
- Audience equals the Credential Issuer Identifier, including its organisation
  path. The credential endpoint URL is not the audience.
- Integer `iat`, at most six minutes old or one minute in the future; optional
  JWT temporal claims are also validated with one minute of clock skew.
- Non-empty `nonce`, validated against the issuer-scoped Redis challenge store.

An `x5c` certificate supplies a key for proof of possession here. Accepting that
key does not establish trust in the wallet provider or in an attestation issuer.
The subsequent [wallet hardening](wallet-security-hardening.md) adds pinned
attester verification. That trust configuration is separate from holder proof
verification and does not establish a complete EUDI/HAIP trust framework.

## Nonces and retries

The public Nonce Endpoint and the legacy nonce returned by the pre-authorized
Token Endpoint share one Redis implementation. Redis must be configured and
available; writes and validations fail closed. The Nonce Endpoint response uses
`Cache-Control: no-store`.

A nonce lasts five minutes and is accepted for one credential request. Multiple
proofs in that request may share it. The issuer first validates every proof,
then uses a Redis Lua script to check and consume all distinct nonces atomically.
No nonce in the set is consumed if one is invalid. Tenant hash tags keep the
script's keys in the same Redis Cluster slot.

Cryptographically invalid or missing proofs return HTTP 400 `invalid_proof`.
Unknown, expired or consumed challenges return HTTP 400 `invalid_nonce`.
Missing/unavailable nonce storage returns HTTP 503 `temporarily_unavailable`.
A wallet receiving `invalid_nonce` must retrieve a fresh challenge and create
new proofs. After consumption, a subsequent signing/storage/webhook failure
also requires a fresh nonce on retry. This policy is deliberately request-level;
it does not require a different nonce for every proof in a batch.

Nonce key names changed. Challenges minted before this update are not accepted;
clients must request fresh ones. Old offer-level database nonce columns are not
deleted or used as an unverified fallback.

## Deferred issuance migration

Migration **000183** adds nullable `identity.deferred_credentials.holder_jwk`.
Apply normal database migrations before running the updated server. The new
column stores the verified public holder key, not just its identifier. The model
omits it from JSON output, and a database constraint rejects private/symmetric
key material. Repository reads, creation and listing include the field.

New offer-based deferred requests persist that key; approval binds the resulting
credential to the same key. Existing pending rows without a key return HTTP 409
on approval and require a new issuance request. They are not automatically
deleted, cancelled, reissued or downgraded to bearer credentials. Already
completed credentials are not rewritten.

The single offer-based deferred endpoint supports one holder proof per request;
multiple proofs are explicitly rejected there. Legacy batch requests can create
separate deferred records, each with its own verified holder key. This change
does not add deferred issuance to the authorization-code path. The follow-up
explicitly rejects configurations requiring unsupported deferred/VP workflows
there rather than silently issuing immediately.

Rolling back migration 183 drops the stored holder keys. Reapplying it cannot
reconstruct keys from old key IDs: affected pending requests must be recreated.

## Validation and remaining boundaries

Regression tests in `internal/handler/oid4vci_proof_test.go` include invalid
signatures, missing/private/symmetric keys, claims, both input forms, certificate
keys, algorithm policy, multi-proof validation, concurrent replay, unavailable
storage, and actual HTTP issuance and deferred approval with PostgreSQL/Redis.
Set `TEST_DATABASE_URL` and `TEST_REDIS_URL` to isolated test services; the
integration cases skip when those variables are absent.

The subsequent [wallet hardening](wallet-security-hardening.md) adds transactional
offer/deferred consumption, configuration authorization, attester pins and strict
mdoc verification. Nonce consumption remains separate from the SQL transaction;
external side effects and network delivery are not an exactly-once guarantee.
Dataset identifiers, full Final profile coverage and deferred token refresh are
still limited as described there. This document records the earlier proof-focused
change; it must be read together with the follow-up for current behavior.

The OpenID suite and real IT-Wallet interoperability must be rerun against the
updated build. Existing suite-specific metadata/encryption adaptations are
preserved. No production deployment is part of this change.

Reference: [OID4VCI 1.0 Final, Sections 7–8, 13.8 and Appendix F](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).

Validation of this change:

- Private module: `go test ./... -race -timeout 5m` passed with a freshly migrated
  PostgreSQL 17 database and Redis 7; includes cached results for unaffected
  packages. Nested Go modules are outside that command.
- Public module: `go test ./internal/handler ./internal/oid4w -run
  '^(TestVCI|TestFinal|TestCredentialCA)' -race -count=1` passed with real test
  PostgreSQL/Redis. This is the selected regression suite, not a full public
  repository test run.
- `go vet ./internal/handler ./internal/repository ./internal/oid4w` passed in
  both modules; public `go build ./cmd/server ./cmd/migrate` passed.
- Migration 183 applied successfully; its down/up SQL was also exercised in a
  rolled-back transaction on the temporary database.
- Database integration tests require a fresh database for repeatable full-suite
  runs: existing billing fixtures reuse fixed subscription IDs. A rerun against
  the reused temporary database failed those fixtures; the clean-database run
  passed. No billing code or financial records were changed.

All service instances used for these checks were temporary local test services.
The OpenID conformance suite and real wallets were not run during this change.
