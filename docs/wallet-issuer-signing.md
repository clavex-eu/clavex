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

## Superadmin administration: mdoc Document Signers

**Superadmin → Signing Keys → Wallet issuing certificates**, after selecting
an organisation, manages the active signer for
mDL, PID mdoc or a custom document type. It supports:

- importing one public P-256 DS certificate, its IACA chain (root last), and
  either one local PEM private key or an authorised Vault Transit profile;
- inspecting certificate expiry, SHA-256 fingerprint and signing backend;
- explicitly replacing an existing signer or confirming its removal.

The UI uses `/api/v1/superadmin/organizations/:org_id/mdoc/issuers` and
`/mdoc/vault-signers` under the same organisation prefix. All signing-management
routes require an authenticated installation superadmin. The former
`/organizations/:org_id/mdoc/issuers` and `/mdoc/vault-signers` URLs remain
available only to superadmins; tenant administrators cannot use them. Verifier
trust-anchor management is separate and retains its existing tenant permissions. Imports validate key/certificate matching, current chain
validity, signing key usage and leaf/root roles. The IACA remains an explicit
configuration input, not evidence that an external wallet trusts the issuer.
The receiving wallet remains responsible for its trust and certificate status
policy; importing a signer does not register a national PID or mDL issuer.

New local-key API writes, including sandbox generation, encrypt the key using
Clavex's configured encryption key. Read responses contain an explicit public
projection and never return private keys. Migration **193** adds a Vault
reference without rewriting existing rows or legacy plaintext keys; the latter
remain readable. Encryption of historical keys requires a separate deliberate
migration. Back up and retain the installation encryption key. Downgrade is
blocked while external references or new encrypted key envelopes remain; an
older binary cannot resolve these signing configurations.

A replacement requires `replace_existing: true`; omission returns HTTP 409 when
an active signer already exists. Existing credentials are not reissued or
revoked. Keep the previous public trust material available to consumers until
old credentials expire; the replacement action is not a trust-distribution or
certificate-rotation protocol. The generator endpoint creates a **sandbox DS
leaf**, not an IACA CA, and also requires explicit replacement confirmation.

mdoc signing now accepts `crypto.Signer`, so Transit signing does not require
exporting a private key. COSE signatures are verified against the configured DS
public key before use. The MSO validity is capped by the configured certificate
chain expiry, and includes intermediate DS certificates when present.

## Vault Transit configuration for mdoc

Only an installation administrator can configure provider connections. Set
`oid4vci.wallet_vault_profiles_file` (environment variable
`CLAVEX_OID4VCI_WALLET_VAULT_PROFILES_FILE`) to an operator-owned JSON file:

```json
[
  {
    "id": "tenant-mdoc-v2",
    "label": "Tenant mdoc signing key",
    "org_id": "11111111-1111-4111-8111-111111111111",
    "address": "https://vault.example:8200",
    "ca_file": "/run/secrets/vault-tls-ca.pem",
    "token_env": "CLAVEX_WALLET_VAULT_TOKEN",
    "namespace": "",
    "mount": "transit",
    "key": "tenant-mdoc",
    "version": 2
  }
]
```

`ca_file` and `namespace` are optional. TLS verification remains enabled and
redirects are not followed. Endpoint addresses, tokens, mount/key paths and CA
files cannot be supplied by a tenant API request. The superadmin sees only the ID, label and pinned version of profiles
authorised for the selected organisation from `GET /mdoc/vault-signers`.
Invalid configuration fails closed; no implicit fallback to a local key occurs.
Configuration is loaded at application startup; editing the file alone does not
reload an already running process.

Use a least-privilege Vault token with `read` on `transit/keys/tenant-mdoc` and
`update` on `transit/sign/tenant-mdoc` (adjust the mount and key). No key creation,
rotation, export, PKI issuance or revocation capability is required by Clavex.
The token value must be supplied outside Git through the named environment
variable. Provision a separate key/profile per tenant where key isolation is
required; cross-tenant assignment is an explicit installation decision.

Resolution checks the pinned version's public key against the DS certificate,
requires `ecdsa-p256`, and rejects exportable keys, plaintext backups and derived
keys. Saving a Vault-backed signer also performs a signing probe. Every returned
signature must have the configured `vault:vN:` envelope and verify against the
DS public key. Vault errors are sanitised; no provider response body or token is
returned to the browser. Requests have bounded timeouts and response sizes.

This integration has automated TLS-backed mock-Vault tests. It has not been
validated against the operator's live Vault instance, and adding configuration
or running migrations is a separate deployment action.

Vault PKI certificate issuance and Transit signing are distinct. PKI's `issue`
operation returns a leaf private key; storing that key in Clavex does **not**
provide non-exportable remote signing. For Transit, arrange certificate issuance
against the existing non-exportable key outside this UI. No CSR, issuance,
renewal, revocation or trust-catalog changes are performed automatically.
[Vault Transit API reference](https://developer.hashicorp.com/vault/api-docs/secret/transit).

## Remaining administration work

Metadata and SD-JWT signing still use the installation file configuration above,
not tenant self-service or this mdoc Transit adapter. Tenant-scoped profiles for
those purposes require preserving historical verification keys for deferred
issuance and local account/CIBA verification during rotation. CSR-based PKI
workflows, renewal, certificate revocation checks at signing time, and broader
algorithm support remain separate work. Do not describe this mdoc panel as
complete management of every wallet certificate.

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

## Credential response encryption and wallet compatibility

On installations with an available RSA request-decryption key, ordinary issuer
metadata now advertises implemented response and request encryption, just as
conformance metadata does. Previously both objects were omitted outside
conformance mode as a workaround for an older iOS wallet; that prevented Android
wallets requiring encryption from starting issuance. No wallet trust check is
relaxed by this change. Re-test older iOS builds separately.

Response encryption supports ECDH-ES, ECDH-ES+A128KW and ECDH-ES+A256KW, with
A256GCM, A128CBC-HS256 or A256CBC-HS512. The response public key and algorithm are
supplied by the wallet. Private keys, unadvertised algorithms, conflicting
algorithm parameters and compression requests are rejected. A plaintext request
can receive a JWE response; encrypted requests use the issuer's advertised
RSA-OAEP-256 key. Deferred encryption retains its encrypted-request requirement.
Remote OIDC signers without an available request-decryption key do not advertise
these capabilities; request decryption for that backend remains separate work.

Automated coverage includes all advertised response-algorithm combinations,
wrong-key decryption rejection, ordinary metadata, and actual credential issuance
with both plaintext and encrypted HTTP requests using temporary PostgreSQL/Redis.
The phone test still needs a fresh offer and refreshed issuer metadata.
