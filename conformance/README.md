# Conformance tooling

[Reproduce an evaluation](REPRODUCIBILITY.md) with your own test installation,
generated keys and the pinned, unmodified OpenID Foundation suite. Public plan
sources are in `templates/`; resolved plans and private material are generated
locally and ignored by Git.

The backend includes the wallet, signing, replay/revocation and discovery fixes
used in the private laboratory evaluation. The port is tested separately: the
historical private-suite results are not a claim that a full official run has
already been repeated against this public build.

[Manual evidence](MANUAL-REVIEW.md) explains screenshot uploads and explicit
per-instance decisions. Neither uploads nor local approvals rewrite official
suite verdicts or increase automatic pass counts. [Historical provenance](HISTORICAL-BASELINE-2026-11-03.md)
retains the original build and suite records. See [porting notes](PUBLIC-PORT-2026-11.md)
for scope, migration requirements and public/private differences.
