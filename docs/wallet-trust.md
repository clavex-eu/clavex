# Tenant mdoc issuer trust

The **Wallet verifier → Issuer trust** view manages the public issuer-authority
CA certificates used by that tenant to validate mdoc credentials. Administrators
can upload a custom CA, inspect its fingerprint, validity and document-type
scope, or remove it with confirmation. These operations use the existing
organisation access and `clients` resource permission checks.

This trust direction is **wallet credential → Clavex verifier**. Adding a CA here
does not make an external wallet trust Clavex as an issuer. SD-JWT issuer trust,
wallet attestation trust, reader authentication and issuer metadata signing are
separate settings and checks.

## Reference development catalogue

`internal/trustcatalog/eudi-reference-test.json` contains seven public development
roots from the European Commission reference Android wallet repository, pinned
to commit `4b295477f69351c1015ae253006bf240dd02d8ef`. Each entry records its source
URL, SHA-256 fingerprint and explicit mDL/PID mdoc scope. Source country/profile
labels are CZ, EE, EU, LU, NL, PT and UT; these are not claims of national
production accreditation. The public certificate files retain their provenance;
no private keys or remote certificate-download service are included.

The catalogue is **not a production trust list, registration or certification**.
Nothing is installed on startup or tenant creation. An administrator must open
the catalogue, acknowledge that the tenant is for tests, then import the missing
authorities. Entries outside their validity period cannot be imported from the
catalogue UI. An intentional custom upload can preload a future CA; credential
verification still enforces certificate validity.

Restoring the catalogue adds only missing fingerprints. Existing authorities
retain their configured document scope and active state, and custom authorities
are preserved. For example, an existing LU authority limited to mDL is not
silently expanded to PID. Remove and explicitly reimport an entry to adopt the
catalogue's scope. A duplicate import returns HTTP 409. A partial batch stops on
the first other failure and reports what was imported; it is not atomic.

The catalogue is bundled and reviewed with the application; there is no automatic
remote refresh or background change to tenant trust. Future certificate rotation
requires reviewing the source material and updating the pins in a code change.

## API and upload safety

All routes are under `/api/v1/organizations/:org_id/mdoc`:

| Method | Path | Behaviour |
| --- | --- | --- |
| GET | `/iaca-roots` | List tenant roots and public certificate metadata |
| POST | `/iaca-roots` | Upload one public CA certificate and explicit scope |
| DELETE | `/iaca-roots/:root_id` | Remove a root belonging to this tenant |
| GET | `/iaca-catalog` | Read the bundled test catalogue; no database writes |

New uploads accept exactly one PEM certificate, at most 64 KiB. Private keys,
bundles, PEM headers and unrelated leading/trailing content are rejected; only
the canonical public certificate is stored. Empty `doc_types` retains the
existing API meaning of all mdoc document types, which the UI requires the user
to select explicitly.

Existing database records are not rewritten and their verifier interpretation
is unchanged. API responses expose only the parsed public certificate, even if
a legacy record contains trailing material. Such records are flagged for manual
review; invalid certificates and fingerprint mismatches are also flagged.

## Verification of this change

Targeted Go race tests cover catalogue provenance, tampering, defensive copies,
upload rejection, legacy response sanitisation and a catalogue read without a
database connection. Chromium tests against mocked API responses exercise
explicit import, missing-only restore, preserved scope, deletion confirmation
and Escape, custom upload, private-key rejection, tenant switching, an API error
and retry, and desktop/mobile layouts. These browser checks do not validate a
live wallet, the deployed API or production trust registration.
