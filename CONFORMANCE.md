# Clavex — OIDF conformance evaluation

Snapshot: **3 November 2026, before the subsequent manual key-rotation run**.

These are the latest instances of 20 plans evaluated in the private laboratory, including targeted reruns on private revision `805e1af3`. They are not a new complete suite run against the public port. See the [reproduction guide](conformance/REPRODUCIBILITY.md) and [original provenance](conformance/HISTORICAL-BASELINE-2026-11-03.md).

There are **604 automatic PASSED**, **72 matching manual approvals**, **6 WARNING**, **30 upstream SKIPPED** and **5 deferred key-rotation cases** (two historical FAILED, three NOT_RUN), across **717 modules**. Raw REVIEW/UNKNOWN verdicts remain unchanged by manual approval. No certification is claimed.

## Summary

| Plan | Tests | Passed | Manual approvals | Warning | Skipped | Failed | Not run |
|---|---:|---:|---:|---:|---:|---:|---:|
| clavex-basic | 35 | 27 | 3 | 0 | 5 | 0 | 0 |
| clavex-basic-post | 36 | 26 | 4 | 0 | 5 | 1 | 0 |
| clavex-config | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| clavex-dynamic | 23 | 11 | 6 | 0 | 5 | 1 | 0 |
| clavex-form-post | 36 | 26 | 4 | 0 | 5 | 0 | 1 |
| clavex-hybrid | 36 | 26 | 4 | 0 | 5 | 0 | 1 |
| clavex-par | 36 | 26 | 4 | 0 | 5 | 0 | 1 |
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

The 72 approvals cover 62 raw REVIEW and 10 UNKNOWN cases with uploaded evidence. They are local operator decisions, not additional automatic PASSED results. The six warnings concern the intentional UserInfo extension claims `groups` and `roles`.

The 30 skips are upstream applicability decisions, including unadvertised address/phone scopes, unsigned variants and pairwise-subject configuration; they are not manually relabelled successes. All five deferred cases require a real key rotation between configuration/JWKS snapshot and Start.

Public tooling contains no laboratory private keys or copied manual-approval registry. Evaluators generate their own fixture material and record their own decisions. Automatic badge counts exclude manual approvals.

[Machine-readable snapshot](conformance/evidence/2026-11-03/pre-rotation-summary.json). The historical June table remains available in Git history.
