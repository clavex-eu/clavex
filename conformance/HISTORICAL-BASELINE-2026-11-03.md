> Historical snapshot: build/public-availability statements below describe the original evaluation, before the public port. For the prepared public implementation, see [the current guide](REPRODUCIBILITY.md).

# Reproducing Clavex conformance evaluations

This guide describes the November 2026 laboratory evaluation using the upstream
OpenID Foundation conformance suite. It separates configuration, product changes,
browser automation, suite verdicts and human evidence so another evaluator can
inspect and repeat the process. A successful run is evidence for the tested
build, configuration and profiles; it is not a certification claim.

## Version scope and availability

| Component | Recorded baseline |
| --- | --- |
| Suite upstream | https://gitlab.com/openid/conformance-suite.git |
| Suite release / commit | `release-v5.3.4` / `23353b36957d6466010de767c812d2c91ed37638` |
| Tested backend source | Private revision `cd9f16cbf42052f794e5f0f7c58135c18df610c3` |
| Tested backend image | `ghcr.io/fcraviolatti/clavex_private:conformance-cd9f16cb` |
| Tested image digest | `sha256:7cf71a12b2c3e81428fe287cd8fe4a5476cc418ad386a5d3f35a5c70cfee2bd9` |
| Laboratory tooling/network correction | Private revision `8deee731` and its ancestors |
| Runner packages | Playwright 1.64.1, requests 2.34.2 |
| Browser | Chrome for Testing 156.0.8078.4 |

**Public-checkout availability:** the public checkout inspected for this guide
was `a641dda`. It does not yet contain the tested backend changes, the current
plan templates or `run-tests.py`. The tested container also required registry
authentication in an anonymous-access check. This guide and its read-only
provenance checker are available publicly; the complete baseline still requires
access to the matching build and tooling, or a later aligned public release.
Do not attribute these results to the current public source or claim that a
fresh public clone already reproduces the November baseline. No private backend
code or credentials are supplied by this documentation change.

The [baseline manifest](evidence/2026-11-03/manifest.json) records these facts and
the selected plan IDs. The [instance index](evidence/2026-11-03/instances.json)
contains only module names, IDs, statuses and verdicts; no tokens, owner details,
private JWKs or credential payloads. New runs will have different IDs, keys,
certificate serials and timestamps. Reproduction means equivalent protocol
outcomes under equivalent prerequisites, not identical identifiers or hashes.

## What the recorded results actually mean

The 20 selected plans contain 717 modules. This is a combined latest-instance
snapshot, including targeted reruns, rather than one uninterrupted invocation.

| Raw stored outcome | Modules |
| --- | ---: |
| PASSED | 594 |
| SKIPPED | 30 |
| INTERRUPTED (including null verdict + interrupted status) | 49 |
| WARNING | 15 |
| Historical FAILED | 2 |
| No instance | 27 |
| Total | 717 |

The operational terminal summary is **594 passed, 0 active failures, 30 skipped,
93 other/pending**. Its two deferred historical failures are key-rotation
instances `fmPEnKKlv7zJNHX` and `y50gH2aMu1GKX8B`. They remain FAILED in the suite;
they were not converted into passes. Rotation must be performed manually between
the module's configuration/JWKS snapshot and Start. When asked to execute that
module, the automation returns local `MANUAL_REQUIRED` without creating one.
The raw instance index deliberately retains those old failures. Depending on run
flags and whether it reads history or execution summaries, a report can show
these two failures instead of the operator's deferred classification.

The 93 remaining outcomes are **not 93 completed manual checks**. They include
warnings, unexecuted modules and interrupted flows. One interrupted issuer
skip-notification case was not identified by the historical screenshot list;
inspect its log before assigning a cause. Only the maintainer can confirm which
manual checks have actually been performed. The hypothetical total 687/717
requires all remaining cases to be executed or validated successfully.

The 30 skips were produced by upstream conditions, not runner exclusions. Their
recorded reasons concern scopes absent from discovery (`address`/`phone`),
unsupported unsigned (`none`) request/ID-token variants, and pairwise-subject
configuration not being advertised. Keep discovery truthful to the deployment;
do not remove an advertised feature simply to obtain a skip. Review applicability
per target profile rather than treating every skip as automatically acceptable.

OID4VP presentation and pre-authorized issuance plans require separate manual
preparation and are not part of this 717-module baseline. HAIP here is issuer
coverage, not an assertion of HAIP verifier coverage. Some installed generic
VCI/VP/Federation plans are alpha/non-certifiable; the aggregate spans distinct
specification families and is not itself a certification profile.

## Verify that the upstream suite was not patched

With the matching tooling checkout:

```sh
git submodule update --init -- .conformance-suite
git -C .conformance-suite rev-parse HEAD
git -C .conformance-suite status --short
git -C .conformance-suite diff HEAD
make conformance-build
python3 conformance/verify_suite.py
```

The first revision must match the pin above; status/diff must be empty. The
checker verifies the official origin, clean source checkout, JAR-recorded commit
and `git.dirty=false`, and calculates SHA-256. The recorded JAR hash is
`1bb3eeb4d7c7f0637438ff99a18e149d38c931d628bd1ce547f1d21ceb7b0883`.

For an independently cloned upstream checkout, including from the public repo:

```sh
git clone --branch release-v5.3.4 --single-branch \
  https://gitlab.com/openid/conformance-suite.git /tmp/oidf-suite
git -C /tmp/oidf-suite checkout 23353b36957d6466010de767c812d2c91ed37638
# Build its JAR using upstream build instructions; then inspect it:
python3 conformance/verify_suite.py --source /tmp/oidf-suite
```

Verify the mounted runtime artifact as well:

```sh
docker exec clavex-conformance-local-server-1 sha256sum /server/fapi-test-suite.jar
```

The recorded checkout was clean and its JAR metadata identifies the exact
upstream commit. These checks are inspectable provenance evidence, not a
cryptographic proof that arbitrary bytecode was built from that source. For
stronger independent verification, rebuild upstream in a controlled environment.
Host/build metadata may cause independently rebuilt JAR hashes to differ.
Skipping Maven's own unit tests while packaging the JAR does not skip the
conformance modules later executed against Clavex; record the build command.

## Product fixes versus laboratory configuration

These results did not come solely from configuration changes. Clavex was also
corrected: examples include client assertion/audience validation, tenant signing
boundaries, encrypted response compression, Status List signing/key discovery,
unpredictable status-slot allocation and mdoc trust/CRL support. These changes
are in the product under test, not edits to upstream expected outcomes. Retain
the tested product revision when comparing results.

Laboratory changes supplied matching clients, callbacks, certificates/trust
anchors, actual CRLs, correct plan field names and reachable DNS/TLS endpoints.
The [automation-policy snapshot](evidence/2026-11-03/automation-policies.json)
records the exact interaction exceptions and deferrals. Its JSON is evidence
about the recorded tooling, not a new runtime override file. Replacing expected
outcomes, suppressing assertions or treating an unreviewed list entry as passed
would be a different procedure and is not supported by these results.

## Prepare a separate laboratory

The following runtime steps require the matching backend/tooling prerequisite
above. Do not run the fixture seed against an existing production database.

1. Provide a disposable PostgreSQL/Redis-backed Clavex installation with HTTPS,
   the required feature entitlement and the selected source revision/image.
   Retain normal license validation. Record edition and enabled capabilities.
2. Configure a dedicated `conformance` tenant with `conformance_mode=true` using
   the supplied seed. This mode expands test metadata/capabilities and fixture
   settings; disclose it when presenting results. It is not evidence for a
   deployment with different settings, and does not justify bypassing validation.
3. Use distinct test clients for basic/post, FAPI DPoP/mTLS/JARM/Final, CIBA and
   VCI. Their auth methods, audiences, keys, TLS bindings and exact callbacks
   must match the corresponding plan. Final audience rules use their dedicated
   registrations; never weaken all clients to satisfy another profile.
4. Configure metadata signing, credential/Status List signing, OIDC signing,
   JAR signing, mdoc IACA/DS and mTLS as distinct roles. Align each plan with the
   matching public trust anchor. Preserve private keys outside version control.
5. Render every plan URL for your own SUT/suite endpoints. Existing templates
   contain this laboratory's `id.clavex.eu` and callback URLs; changing only
   `--op-base` does not rewrite them (that runner option is compatibility-only).
   Match VCT/configuration IDs and algorithms to the actual discovery metadata.

On a **fresh** test database, with database/configuration environment set for it:

```sh
go run ./cmd/migrate --config "$TEST_CONFIG" up
go run ./cmd/conformance-seed --config "$TEST_CONFIG"
go run ./cmd/conformance-seed --config "$TEST_CONFIG" \
  --mdoc-pki-only --key-dir conformance --fixture-base-url "$SUT_ORIGIN"
go run ./cmd/conformance-federation-keys
```

Set `TEST_CONFIG` to the intended test YAML and `SUT_ORIGIN` to its HTTPS origin.
Ensure `CLAVEX_CONFIG` does not override that file and any database environment
settings target the same disposable installation for both commands.
The full seed creates/updates fixtures and may reset test users/registrations;
it is not a read-only preparation check. In an existing lab use the explicit
targeted modes after reviewing their effects. `--mdoc-pki-only` reissues only
the test tenant's mDL certificates with matching existing local keys, registers
the public IACA, publishes its CRL and updates the two mdoc plan anchors.
`--mdoc-crl-only` refreshes that active IACA's CRL while preserving revoked
serials. Renew it before nextUpdate. Neither command silently replaces keys.

## Network and trust configuration

Use the suite hostname in certificates and callbacks consistently. Its dev-mode
UI must be confined to your chosen laboratory network. The supplied Compose
override is **specific to the recorded host**: loopback, LXD `10.100.0.1` and
WireGuard `192.168.27.71`. Replace bindings/host mappings for another installation.

There are three distinct routes to verify: browser/runner → SUT and suite;
SUT → suite RP/TA endpoints; and Java suite container → its own nginx endpoint.
In the recorded host, all suite-internal/cluster routes use `10.100.0.1:8443`.
Docker `host-gateway` resolved to `172.17.0.1`, where 8443 was not published;
correcting that mapping fixed connection refusals without changing assertions.

```sh
# Creates or validates the local CA/server certificate; preserves valid existing keys.
bash conformance/setup-local-tls.sh
make conformance-up
export SUITE_URL=https://localhost.emobix.co.uk:8443
export SUITE_CA_FILE="$PWD/conformance/.local/tls/ca.pem"
curl --fail --cacert "$SUITE_CA_FILE" "$SUITE_URL/api/plan/available" >/dev/null
make conformance-tools
```

Trust only the generated **public** CA in the browser and backend trust store;
retain system roots. The recorded backend uses
`SSL_CERT_DIR=/etc/ssl/certs:/etc/clavex/conformance-ca`. Verify the suite from
the actual Java container and the backend network, not only from the host.
For a backend running in Kubernetes, create its CA ConfigMap from **your generated
public CA**, not a certificate copied from the recorded laboratory:

```sh
kubectl -n "$TEST_NAMESPACE" create configmap clavex-local-conformance-ca \
  --from-file=ca.pem="$SUITE_CA_FILE" --dry-run=client -o yaml > /tmp/suite-ca.yaml
# Review the namespace and certificate, then apply to the test installation:
kubectl apply -f /tmp/suite-ca.yaml
```

Merge these fields into the backend Helm values, preserving existing entries,
and roll out that test backend through its normal deployment procedure:

```yaml
extraEnv:
  - name: SSL_CERT_DIR
    value: /etc/ssl/certs:/etc/clavex/conformance-ca
extraVolumes:
  - name: local-conformance-ca
    configMap:
      name: clavex-local-conformance-ca
extraVolumeMounts:
  - name: local-conformance-ca
    mountPath: /etc/clavex/conformance-ca
    readOnly: true
```

Import the public `ca.pem` into the browser/OS certificate-authority store using
that platform's certificate manager. Never import or distribute `ca.key`.
Check Java-container routing independently (the temporary copy is public):

```sh
docker cp "$SUITE_CA_FILE" clavex-conformance-local-server-1:/tmp/suite-ca.pem
docker exec clavex-conformance-local-server-1 curl --fail \
  --cacert /tmp/suite-ca.pem "$SUITE_URL/api/plan/available" -o /dev/null
docker exec clavex-conformance-local-server-1 rm /tmp/suite-ca.pem
```

Also execute the equivalent `curl --fail --cacert /path/to/mounted/ca.pem`
request from the backend's network, using a diagnostic container if the backend
image lacks curl. Confirm DNS resolves to the reachable suite interface there;
a successful host-only check is insufficient.
Do not use `SUITE_INSECURE=1` for the verified baseline. Chromium's exception is
limited to the suite certificate SPKI after verifying it against the CA.

For Federation, configure the explicit installation-operator setting:

```text
CLAVEX_FEDERATION_CONFORMANCE_TRUST_ANCHOR=https://localhost.emobix.co.uk:8443/test/a/clavex-openid-federation-op/trust-anchor
```

It applies only to the existing test tenant in conformance mode. Other tenant
trust is unchanged. The local routing allowance is restricted to this HTTPS
origin and alias; TLS verification remains enabled. This creates a laboratory
trust relationship, not membership in a national/European production federation.

## Configure, execute and preserve results

The following Bash commands create only the 20 baseline aliases. Inspect/render
templates for your endpoints first; plan creation writes configurations to the
suite. The subsequent execution deliberately starts fresh instances.

```sh
make conformance-check-config
mkdir -p conformance/.local
python3 - <<'PYALIASES' > conformance/.local/baseline-aliases.txt
import json
with open("conformance/evidence/2026-11-03/manifest.json") as f:
    for plan in json.load(f)["plans"]:
        print(plan["alias"])
PYALIASES
while IFS= read -r alias; do
  bash conformance/create-plans.sh --only-alias="$alias" --dry-run || exit 1
done < conformance/.local/baseline-aliases.txt
# Review dry-run output before this upload loop.
while IFS= read -r alias; do
  bash conformance/create-plans.sh --only-alias="$alias" || exit 1
done < conformance/.local/baseline-aliases.txt
```

Read back the newly created plans in the suite UI and copy their exact IDs, one
per line, into `conformance/.local/baseline-plan-ids.txt`. Match each of the 20
aliases above once, including its variant; do not reuse this snapshot's IDs.
Then run precisely those plans, rather than a substring filter such as `basic`
(which can also match `basic-post`):

```sh
while IFS= read -r plan_id; do
  make conformance-run-tests ARGS="--plan $plan_id --jobs 1 --timeout 180 --rerun" || exit 1
done < conformance/.local/baseline-plan-ids.txt
```

Plan upload creates configurations, not passing results. New suite releases can
change counts. For a focused retry use `--plan EXACT_ID --rerun-failed`. The
runner's default selects newest plans by creation timestamp and can include
additional aliases outside this baseline; exact IDs avoid that scope ambiguity.

Modules within a plan stay sequential. `--jobs 2` can overlap independent plans;
shared clients, Federation, logout, CIBA and unknown allocations remain exclusive.
Use one runner process. `--skip-manual-evidence` defers listed modules *before*
creating instances, recording local `MANUAL_REQUIRED`, never PASSED or SKIPPED.

The exact browser exceptions are inspectable in `browser-behaviors.json`:
user-rejection modules cancel; request-URI reuse modules visit without login
first and log in on the next visit; the CIBA expiry module avoids interaction.
These reproduce the requested user scenarios. They do not alter suite conditions
or responses. `_remap_result` is an identity function; browser navigation itself
does not award PASSED. Timeouts/browser errors stay distinct from suite verdicts.

Read status and generate a report without starting modules:

```sh
make conformance-status
python3 conformance/update-conformance-md.py --suite-url "$SUITE_URL" \
  --out conformance/.local/current-results.md
```

The general status/report commands can include other plans in the suite; their
aggregate need not equal this 20-plan baseline. Reconcile against the selected
IDs before publishing a comparison.

Preserve per-instance suite exports/logs, both `status` and `result`, plan
configuration/variants, SUT revision/digest, suite commit/JAR hash, discovery,
certificate fingerprints, dependency versions and runner command/flags. Record
whether results were resumed/retried. Keep raw exports privately first: plan
configs/logs may contain test private keys, credentials, tokens or personal data.
Publish a sanitized copy and document redactions; preserve the original for review.
Do not export production keys. Raw API results and local summary classifications
must remain distinguishable. Badges and `CONFORMANCE.md` are derived reports,
not independent evidence and not substitutes for raw exports.

## Evidence availability and remaining gaps

The published index supports the recorded status/count reconciliation. It is
not a complete audit package: raw per-condition logs, full plan configuration
exports, historical shell invocations and completed human review evidence are
not supplied here. Configuration hashes identify local files, but cannot let an
external reader inspect an unpublished configuration. Independent verification
of every assertion requires a fresh run with accessible matching tooling/build,
or access to sanitized full exports and the corresponding evidence. Preserve
those artifacts on the next run; do not reconstruct missing historical records.

## Human evidence and certification scope

`screenshot-required.txt` is a historical operator review list. Membership alone
does not prove the current build passes, and the current runner does not use it
to turn official verdicts into passes. `manual-evidence.json` is a separate
deferral policy. Neither is an upstream expectation override.

For each manual validation record the module/plan/instance, SUT and suite
versions, expected screen/behaviour, observed result, reviewer/date and screenshot
or other evidence. Distinguish a reviewed local assertion from a FINISHED suite
instance. An interrupted case may need a fresh instance and timely evidence.
Preserve warnings and investigate incomplete cases rather than assuming all
need only screenshots. Attach the required evidence in the suite when preparing
an official submission; a local file is not that submission.

References: [upstream source](https://gitlab.com/openid/conformance-suite/-/tree/23353b36957d6466010de767c812d2c91ed37638),
[OIDF instructions](https://openid.net/certification/instructions/),
[OIDC OP submission](https://openid.net/certification/op_submission/).
Eligibility and evidence requirements are assessed per profile, not by an
aggregate percentage across 717 modules. This documentation does not claim that
the laboratory conformance mode or self-issued test CAs represent eIDAS/EHDS
certification, ecosystem trust or production readiness.
