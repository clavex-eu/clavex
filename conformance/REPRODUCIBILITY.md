# Reproducing Clavex conformance evaluations

Current reporting follow-up: [all five server-key rotations passed](ROTATION-RESULTS-2026-11-03.md); [609 automatic passes and 72 separate visual approvals](evidence/2026-11-03/post-rotation-summary.json). Historical pre-rotation evidence remains unchanged.

The public implementation includes the product and runner corrections evaluated
in the private November 2026 laboratory. Reproduction requires the same protocol
profiles and equivalent configuration on your own test installation. Fresh runs
will have different identifiers, private keys, certificates and timestamps.

The reference suite is **release-v5.3.4**, upstream commit
`23353b36957d6466010de767c812d2c91ed37638`, from
https://gitlab.com/openid/conformance-suite.git. `make conformance-build` checks
out that commit and builds it without patching suite source or assertions.
`python3 conformance/verify_suite.py` verifies the clean checkout, JAR commit
metadata and digest. It is a provenance check, not a certification verdict.

## Prepare fresh local fixtures

Use a dedicated test database and installation. The seed creates known test
accounts and updates registrations; it is not a read-only operation. Do not run
it against a production tenant database. Configure the same test database and
Redis for migration, seed and backend commands.

```sh
make conformance-tools  # reproduction environment: Python 3.12
make conformance-fixtures ARGS="--backend-origin https://issuer.example --suite-origin https://localhost.emobix.co.uk:8443"
```

Replace `https://issuer.example` with your actual HTTPS backend origin. The
fixture command only writes local files: it contacts no service, changes no
trust and starts no test. It renders the 29 public templates into ignored
`conformance/*-plan.json` files, generates distinct wallet/attestation keys and
laboratory certificates, and retains private material under `conformance/.local/`
with restricted permissions. Repeating it preserves its generated key material;
use another output directory for a different origin. Run it before seeding;
re-rendering plans afterward overwrites seed-populated configuration and requires
seeding again. Never commit or share resolved plans or the private cache.

The generated certificates establish **laboratory** trust only. They are not
national PID/mDL issuer credentials or EUDI relying-party authorisations.

## Configure the test backend and seed

Set the backend's issuer configuration to the chosen HTTPS origin. Configure its
certificate-backed credential and metadata signers using absolute paths visible
to that backend process (mount them explicitly when containerised):

```sh
export CLAVEX_OID4VCI_CREDENTIAL_CERT_FILE="$PWD/conformance/.local/issuer-cert.pem"
export CLAVEX_OID4VCI_CREDENTIAL_KEY_FILE="$PWD/conformance/.local/issuer-key.pem"
export CLAVEX_OID4VCI_METADATA_CERT_FILE="$PWD/conformance/.local/metadata-cert.pem"
export CLAVEX_OID4VCI_METADATA_KEY_FILE="$PWD/conformance/.local/metadata-key.pem"
```

The plans use the generated public issuer root for credential/Status List trust.
The mTLS test plans carry distinct generated client certificates: configure your
mTLS termination to verify their public issuer root and forward verified client
certificate information through Clavex's trusted-proxy configuration. A plain
header supplied by an untrusted client is not a verified mTLS identity.

Set `TEST_CONFIG` to your test YAML and `SUT_ORIGIN` to the chosen HTTPS origin.
Ensure `CLAVEX_CONFIG`/database environment variables do not override that target.

```sh
go run ./cmd/migrate --config "$TEST_CONFIG" up
go run ./cmd/conformance-seed --config "$TEST_CONFIG"
go run ./cmd/conformance-seed --config "$TEST_CONFIG" \
  --mdoc-pki-only --key-dir conformance --fixture-base-url "$SUT_ORIGIN"
go run ./cmd/conformance-federation-keys
make conformance-check-config
```

The full seed creates the dedicated Final clients, distinct FAPI keys and wallet
registrations; it synchronises resolved plans with the generated public keys.
The explicit mdoc command provisions the conformance tenant's mDL certificate
profile and signed IACA CRL and updates the two plan trust anchors. It retains
matching local private keys. Refresh the CRL before its `nextUpdate` using the
separate `--mdoc-crl-only` mode. For an existing lab, use the targeted provisioning
modes after reviewing their effects instead of blindly reseeding.

## Suite, routing and verified TLS

```sh
make conformance-build
make conformance-up
export SUITE_URL=https://localhost.emobix.co.uk:8443
export SUITE_CA_FILE="$PWD/conformance/.local/tls/ca.pem"
curl --fail --cacert "$SUITE_CA_FILE" "$SUITE_URL/api/plan/available" >/dev/null
python3 conformance/verify_suite.py
```

The public Compose override binds only loopback, uses the separate project
`clavex-conformance-public`, and gives nginx a Docker-network alias for the suite
origin. It contains no LXD, VPN or Kubernetes address from the recorded lab.
This requires Docker Compose with `!override` support. A remote backend needs an
explicitly reachable suite listener and matching DNS; adapt bindings and TLS SANs
for your own network. The runner/browser must reach both systems, the backend
must reach suite RP/TA endpoints, and the Java container must reach nginx.

Trust the generated **public** suite CA in the runner, browser and backend while
retaining system roots. Never distribute `ca.key`. For remote/container backends,
mount the public CA and use the normal OS/Go trust-store configuration; verify
connectivity from that network, not only the host. No command here disables TLS
verification. `SUITE_CA_FILE` is used by requests/curl and the browser runner's
scoped certificate handling.

Federation additionally requires the explicit backend operator setting:

```text
CLAVEX_FEDERATION_CONFORMANCE_TRUST_ANCHOR=https://localhost.emobix.co.uk:8443/test/a/clavex-openid-federation-op/trust-anchor
```

It applies only to the `conformance` tenant with conformance mode enabled. The
private-routing exception is restricted to that HTTPS origin and alias, with TLS
verification still active. Other tenants retain their configured trust. This is
laboratory Federation trust, not production federation membership.

## Create and execute plans

Plan upload does not reseed, rotate keys or start tests. Inspect the dry run first.
To reproduce the 20-plan recorded scope rather than every available optional plan:

```sh
bash conformance/create-plans.sh --dry-run
python3 - <<'PYALIASES' > conformance/.local/baseline-aliases.txt
import json
with open('conformance/evidence/2026-11-03/manifest.json') as stream:
    for plan in json.load(stream)['plans']:
        print(plan['alias'])
PYALIASES
while IFS= read -r alias; do
  bash conformance/create-plans.sh "--only-alias=$alias" || exit 1
done < conformance/.local/baseline-aliases.txt
make conformance-run-tests ARGS="--jobs 2 --upload-screenshots --timeout 180"
```

For an online suite, set `SUITE_URL` and `SUITE_TOKEN` in the environment; never
commit the token. Review its supported plan catalogue before uploading.
`--jobs` schedules independent plans, serialises shared client/state operations
and keeps each plan's modules sequential. The exact browser exceptions in
`browser-behaviors.json` implement cancellation or an initial unauthenticated
visit where the test requires it; they never change assertions or verdicts.

Key rotation needs configuration/JWKS snapshot, a real operator rotation, then
Start in the suite UI. The runner leaves it `MANUAL_REQUIRED`, creating no
instance. Verifier and pre-authorised issuance plans need fresh manual inputs
and are outside the recorded 717-module issuer/OP baseline.

For one existing plan/module:

```sh
make conformance-run-tests ARGS="--plan EXACT_PLAN_ID --module COMPLETE_MODULE_NAME --rerun --upload-screenshots --timeout 180"
```

The module argument is a substring filter: inspect the selection first. Old
instances remain stored. Screenshots are attached to official placeholders, not
approved automatically. Use the [manual workflow](MANUAL-REVIEW.md) for explicit
per-instance approvals; changed verdicts or evidence invalidate old approvals.

## Reporting and interpretation

`make conformance-status` and `conformance/update-conformance-md.py` select the
latest plan per alias consistently. Reports separate automatic PASSED, warnings,
REVIEW/UNKNOWN, FAILED and upstream SKIPPED. Manual approvals remain separately
visible and do not alter badge pass counts. The historical screenshot-name list
is not a pass override.

The [historical record](HISTORICAL-BASELINE-2026-11-03.md) and original evidence
manifest identify the private build used for that evaluation. The public port
has separate Go, browser/tooling and build checks; it has not inherited a full
717-test run merely by containing equivalent fixes. The maintainer's subsequent
key-rotation review is a separate execution. Some upstream plans are alpha/non-
certifiable, and the aggregate spans multiple profiles. No certification is
claimed from this combined result set.
