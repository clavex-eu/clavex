# Wallet issuer signing certificates

OID4VCI metadata signing, SD-JWT credential signing, mdoc Document Signers,
OIDC token signing and OID4VP request signing have distinct purposes. Configuring
trust anchors in **Wallet verifier → Issuer trust** does not configure any of
these private signing keys and does not make a wallet trust Clavex as an issuer.

## Current implementation

An installation administrator can configure dedicated metadata and SD-JWT
certificate/key files through `oid4vci.metadata_cert_file`, `metadata_key_file`,
`credential_cert_file`, and `credential_key_file`; corresponding environment
variables use the `CLAVEX_OID4VCI_` prefix. All four settings are optional.

Each chain file is PEM, leaf first and self-signed root last. Key/certificate
matching, certificate signatures/order, validity, leaf signing usage and the
issuer DNS SAN are checked. The JWT includes the leaf/intermediates in `x5c`,
excluding the root. Metadata uses the Final `openidvci-issuer-metadata+jwt` type.
Its expiry is capped by the chain expiry. SD-JWT signing uses the configured
algorithm (P-256 ES256 or RSA PS256), includes the configured chain and caps the
credential expiry by certificate expiry. OAuth tokens retain their existing key.

Configured material is revalidated at use time. Invalid configured signing
material produces an error; it never silently falls back to the legacy signer.
With the options absent, the existing signing configuration is retained.
The public credential-issuer CA endpoint exposes the dedicated credential
signer's root when configured. A wallet must independently trust that root.

The local verifier retains the previous OIDC key for previously issued
credentials and recognises the configured dedicated credential public key.
Selection of the new key requires a verified signature and the expected tenant
issuer. Embedded JWKs, certificate chains or unverified `kid` values do not
establish local trust. CIBA/DCQL holder, account binding and status checks remain
in place.

mdoc uses its existing tenant/document-type DS configuration, through
`GET/POST /api/v1/organizations/:org_id/mdoc/issuers`. A DS keypair must be
configured for each intended document type; metadata signing does not create it.

## Administration UI and Vault: open work

The current CA management UI only manages **verifier trust anchors**. There is
no complete UI to configure metadata/SD-JWT signing pairs, and the existing mdoc
management API has no corresponding management panel. Do not describe the file
configuration above as tenant self-service.

Vault PKI can issue the public signing certificates and publish their CRLs.
Issuing a leaf with Vault PKI's `issue` operation returns a private key; storing
that leaf/key in Clavex does **not** provide non-exportable remote signing.
Keeping only the root CA key in Vault also does not keep leaf signing keys there.

Clavex has an existing OIDC RSA Transit adapter, but these new file-backed wallet
signers are not connected to it. Wallet remote signing needs its own tested
certificate/key binding and explicit key-version handling. The current mdoc
model stores DS private keys as PEM in the database (the API excludes this field
from JSON); it needs a migration to encrypted storage or remote key references
before presenting this as hardened production key custody.

Recommended next work, in order:

1. Add tenant-scoped signer profiles for metadata, SD-JWT and mdoc, with explicit
   permissions, public certificate metadata and safe rotation. Preserve old
   verification keys and existing tenant records; no implicit replacement.
2. Add Vault provider connections managed server-side. Store protected
   credentials outside browser responses; allow tenants to select only providers
   and key references authorised for them. Pin Transit key versions and verify
   that each certificate matches the remote public key. Do not accept arbitrary
   tenant-controlled URLs, paths or cross-tenant key names.
3. Support non-exportable Transit/HSM signing and CSR-based PKI issuance, then
   add the matching UI: certificate import, backend selection, CSR, status and
   expiry, and an explicit rotation action. PKI issuance/revocation and Transit
   signing must be shown as separate operations.
4. Test authorisation, isolation, key mismatch, Vault failure/rotation, expired
   or revoked certificates, and that no private key or provider token is returned
   by read APIs, audit logs or browser error messages.

This is an implementation gap, not a completed UI/Vault feature.

## Interoperability limits

The laboratory Android profile pins explicit test signing leaves and the Clavex
test CA. It validates those chains with PKIX and a signed current CRL, and rejects
stale/revoked chains. Unrelated issuers retain the reference application's ETSI
development trust configuration. The profile is opt-in, debug-only, and excluded
from release builds. It does not register Clavex as a national PID or mDL issuer.

The reference wallet uses `urn:eudi:pid:1` for its PID SD-JWT profile and
`eu.europa.ec.eudi.pid.1` for PID mdoc. Correcting the SD-JWT template does not
retroactively edit existing credential configurations or offers. The present
database uniqueness of tenant/VCT also needs consideration when an old SD-JWT
configuration occupies the mdoc PID type; do not silently repurpose that record.

Passing certificate checks is necessary but does not prove that document claims,
national profiles, registration, lifecycle behaviour or every wallet use case
interoperate. A fresh device issuance/presentation test remains necessary.
