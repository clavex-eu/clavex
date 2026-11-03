# Public port of the November 2026 conformance fixes

The private source range `a6501fad..805e1af3` supplies the product corrections.
Each common file was compared with the public baseline after normalising the Go
module import path. Forty-four files shared that baseline; differing server,
configuration, model, key-rotation UI and OpenAPI files were merged against their
own public versions. New tests and helpers use `github.com/clavex-eu/clavex`.

## Product changes

- Tenant-specific OIDC/PQC signer selection, consistent Hybrid/JARM and token
  verification, signing snapshots and safe retention/cache behaviour on rotation.
- Tenant key management belongs to an administrator of that tenant, with the
  existing security permissions. Installation superadmins manage installation
  keys separately. The tenant UI exposes immediate supported rotations and
  distinguishes unavailable/BYOK operations; the superadmin UI is labelled for
  installation keys. Existing signing-key URL shapes remain, but installation
  accounts no longer administer ordinary tenant signing keys.
- Explicit client assertion profiles distinguish standard and FAPI Final
  audience/time requirements; PAR alone does not select Final. Attestation PoP
  handling and ETSI indexed attested proof keys are retained with verification.
- Credential responses support explicit compression alongside encryption.
  Status Lists publish certificate-backed signing material. Status slots are
  allocated unpredictably with transaction-safe reservation and rollover.
- Tenant-scoped mdoc IACA CRL publication, profile-aware test mDL provisioning and
  controlled laboratory Federation registration/routing with verified TLS.
- JWT credential issuance checks revocation. Authenticated authorization-code
  replay invalidates the associated token/grant state synchronously; wrong
  clients/verifiers/senders cannot invalidate legitimate tokens. Distinct grants
  remain separate; legitimate refresh and deferred delivery retain coverage.
- Dynamic registration validates, persists and returns client logo/privacy/terms
  metadata; the requesting application's identity appears alongside tenant
  branding, including failed-login re-renders. Discovery derives active tenant
  credential scopes and advertises the supported ACR `0`; Hybrid is consistent.

Migrations **194 and 195** are required after the public wallet schema 193. They
add random status-slot reservation and mdoc IACA CRL storage. Run the normal
migrator before the application. Review migration notes/code before downgrading:
unsafe status allocation rollback is deliberately rejected. No fixture command
or migration rotates installation keys or imports production trust implicitly.

## Public-specific adaptation

Private billing/cloud provisioning routes, Device CA UI differences, licensing,
ownership and IP rules remain as they were in the public repository. The port
contains no private cluster/VPN manifests, CA keys, resolved plans, production
credentials or local human-review registry. The private SDK work is separate.

Portable conformance scripts preserve upstream outcomes, report SKIPPED
separately, schedule independent plans safely, attach screenshots and record
explicit per-instance human decisions. Source plans are sanitised public
templates. `cmd/conformance-fixtures` generates new local wallet/attestation and
issuer/mTLS material instead of publishing laboratory secrets. Full test-tenant
seeding and targeted PKI provisioning remain explicit actions.

The suite checkout is pinned by Make to the same upstream commit; public Compose
binds loopback and uses its own project name. Network/trust configuration must be
adapted to the evaluator's backend. No deployment manifests for the recorded
installation are copied into this port.

## Verification scope

Validation is against this public module and public route set, with disposable
PostgreSQL/Redis services, offline fixtures, browser/runner regression tests and
a frontend build. The fresh-fixture workflow is checked through initial seed,
targeted mdoc PKI provisioning and read-only plan/key/certificate validation.

The [recorded private suite snapshot](../CONFORMANCE.md) is kept separate from
these public-port checks. No live official suite execution, cluster change,
manual approval, key rotation or deployment is performed by port preparation.
The maintainer's concurrent manual key-rotation evaluation is outside that
snapshot. Repeating the official plans against a public build remains an
independent evaluation; equivalent code does not manufacture equivalent verdicts.

Validation completed locally:

- `go test ./... -p=4 -race -count=1 -timeout 10m`: all packages passed;
  the handler package completed in 322.253 s.
- `go vet ./...` and golangci-lint with the project Go toolchain: passed,
  zero lint issues.
- OpenAPI coverage: all 598 public routes documented.
- 33 Python tooling/browser regression tests passed; final fixture-generator
  tests also passed after the last output-preservation guard.
- `npm run build`: passed; the existing large-bundle advisory remains.
- A fresh disposable database migrated to 195, initial conformance seed and
  targeted mdoc provisioning succeeded; read-only checks accepted 27 suite plan
  configurations and 27 certificates with distinct FAPI keys and consistent
  key-attestation trust.

The checked Python tool versions are pinned in `requirements.txt`. Resolved
plans, private fixture material and test database state are excluded from Git.
