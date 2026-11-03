# Server-key rotation follow-up — 3 November 2026

Read-only verification after the maintainer's manual rotations. No test was started, no key rotated and no approval recorded by report generation. Upstream source/JAR provenance was rechecked at `23353b36957d6466010de767c812d2c91ed37638`; the recorded JAR hash is unchanged.

## Confirmed latest instances

| Plan | Module | Instance | Suite status | Suite result | Started UTC |
|---|---|---|---|---|---|
| clavex-basic-post | `oidcc-server-rotate-keys` | `3fPNiSsqtbGImcK` | FINISHED | PASSED | 2026-11-03T22:35:57.410055431Z |
| clavex-dynamic | `oidcc-server-rotate-keys` | `jl4TOwUhxaK2hqT` | FINISHED | PASSED | 2026-11-03T22:36:23.165640666Z |
| clavex-form-post | `oidcc-server-rotate-keys` | `RcaaiYyuDyRi5Lv` | FINISHED | PASSED | 2026-11-03T22:36:53.164607599Z |
| clavex-hybrid | `oidcc-server-rotate-keys` | `owuHOvnmj739JZs` | FINISHED | PASSED | 2026-11-03T22:38:05.810146078Z |
| clavex-par | `oidcc-server-rotate-keys` | `UIjowIQtqmUD5WJ` | FINISHED | PASSED | 2026-11-03T22:41:07.078910319Z |

These replace two failed and three previously unexecuted plan/module slots in the latest-instance summary. Historical failures remain in the suite and pre-rotation evidence. The five new verdicts are automatic suite PASSED outcomes following required operator actions, not manual approvals or waived failures.

The initial unsuccessful attempt targeted a different tenant. Its new key was published only by that tenant, while the conformance issuer's JWKS correctly remained unchanged. Repeat the test using an administrator of the same issuer tenant whose discovery URL the plan observes: configure a fresh instance, rotate that tenant's OIDC key, then Start. The test must not be made to pass by sharing keys across tenants.

## Updated consolidated evidence

- 609 PASSED; 62 REVIEW; 10 UNKNOWN; 6 WARNING; 30 SKIPPED; 0 FAILED; 0 NOT_RUN.
- 72 existing visual approvals remain valid against their current instance/image evidence.
- 717 configured records across the same 20 plans; multiple executions and repeated module definitions across variants.
- Private backend revision `805e1af3`; updated private frontend revision `805e1af3`. Not a full run against the public tag or a formal certification.

[Current summary](evidence/2026-11-03/post-rotation-summary.json), [latest instance index](evidence/2026-11-03/post-rotation-instances.json), [unchanged earlier summary](evidence/2026-11-03/pre-rotation-summary.json), [main report](../CONFORMANCE.md).
