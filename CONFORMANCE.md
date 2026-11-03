# Clavex — OIDF conformance evaluation

Snapshot: **3 November 2026, after the five manual server-key rotation scenarios**. Collected at `2026-11-03T22:47:07.700464+00:00`.

Latest-instance composite of **20 selected plans / 717 configured plan-module records**, including repeated modules across profile variants and targeted reruns. These are not 717 unique test definitions and not a single uninterrupted run. The laboratory backend is private revision `805e1af3`; this is not a complete official-suite execution against the public tag. Suite: `release-v5.3.4`, commit `23353b36957d6466010de767c812d2c91ed37638`.

**609 automatic PASSED**, **72 matching manual visual-evidence approvals**, **6 WARNING**, **30 upstream SKIPPED**, **0 FAILED**, **0 NOT_RUN**. All five formerly outstanding server-key rotation scenarios are now `FINISHED / PASSED`. Their required manual operations did not turn them into screenshot approvals: their assertions passed in the suite. No official certification is claimed.

## Summary

The “Tests / records” column counts configured plan/module slots. Manual approvals are separate from the Passed column and do not increase automatic badge counts.

| Plan | Tests / records | Passed | Manual approvals | Warning | Skipped | Failed | Not run |
|---|---:|---:|---:|---:|---:|---:|---:|
| clavex-basic | 35 | 27 | 3 | 0 | 5 | 0 | 0 |
| clavex-basic-post | 36 | 27 | 4 | 0 | 5 | 0 | 0 |
| clavex-config | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| clavex-dynamic | 23 | 12 | 6 | 0 | 5 | 0 | 0 |
| clavex-form-post | 36 | 27 | 4 | 0 | 5 | 0 | 0 |
| clavex-hybrid | 36 | 27 | 4 | 0 | 5 | 0 | 0 |
| clavex-par | 36 | 27 | 4 | 0 | 5 | 0 | 0 |
| clavex-fapi | 58 | 51 | 6 | 1 | 0 | 0 | 0 |
| clavex-fapi-mtls | 49 | 42 | 6 | 1 | 0 | 0 | 0 |
| clavex-fapi-jarm | 71 | 64 | 6 | 1 | 0 | 0 | 0 |
| clavex-oid4vci-issuer | 14 | 14 | 0 | 0 | 0 | 0 | 0 |
| clavex-oid4vci-issuer-encrypted | 15 | 15 | 0 | 0 | 0 | 0 | 0 |
| clavex-fapi2-ciba-poll | 34 | 34 | 0 | 0 | 0 | 0 | 0 |
| clavex-fapi-final-dpop | 52 | 45 | 6 | 1 | 0 | 0 | 0 |
| clavex-fapi-final-mtls | 43 | 36 | 6 | 1 | 0 | 0 | 0 |
| clavex-fapi-jarm-final | 66 | 59 | 6 | 1 | 0 | 0 | 0 |
| clavex-haip | 63 | 57 | 6 | 0 | 0 | 0 | 0 |
| clavex-oid4vci-issuer-mso-mdoc | 14 | 14 | 0 | 0 | 0 | 0 | 0 |
| clavex-oid4vci-issuer-mso-mdoc-encrypted | 15 | 15 | 0 | 0 | 0 | 0 | 0 |
| clavex-openid-federation-op | 20 | 15 | 5 | 0 | 0 | 0 | 0 |

The 72 maintainer approvals cover 62 raw REVIEW and 10 UNKNOWN records with matching uploaded visual evidence. They are expected visual-review scenarios, not waived failures; raw verdicts remain unchanged. The six warnings concern the intentional UserInfo extension claims `groups` and `roles`.

The 30 skips are upstream applicability decisions, including unadvertised scopes, unsigned variants and pairwise-subject configuration. They are not manually relabelled successes. Applicability remains profile-specific.

## Server-key rotations

All five `oidcc-server-rotate-keys` records now pass in basic-post, dynamic, form-post, hybrid and PAR. The operator rotated the issuer tenant’s OIDC key between the test’s initial JWKS snapshot and Start. Rotation in a different tenant correctly leaves the observed issuer's JWKS unchanged.

See the [rotation follow-up](conformance/ROTATION-RESULTS-2026-11-03.md) for instance IDs and the [current machine-readable summary](conformance/evidence/2026-11-03/post-rotation-summary.json). The [sanitised instance index](conformance/evidence/2026-11-03/post-rotation-instances.json) records all selected latest instances. The [604-pass pre-rotation summary](conformance/evidence/2026-11-03/pre-rotation-summary.json) is retained unchanged; old failed instances were not deleted or reclassified.

The separate October VP/pre-authorised issuance evaluations are not added to this aggregate. HAIP results here cover the configured SD-JWT issuer; generic mdoc issuer successes do not establish every HAIP/ISO mdoc requirement. The Federation OP plan is alpha/non-certifiable. No later suite-master or SD-JWT VC draft-23 validation is implied.

Use the [reproduction guide](conformance/REPRODUCIBILITY.md) for the applicable environment and version scope. Equivalent implementation and configuration enable an independent evaluation; they do not manufacture identical verdicts.
