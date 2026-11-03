# Conformance reproduction and evidence

Start with [Reproducing Clavex conformance evaluations](REPRODUCIBILITY.md).
The [November baseline](evidence/2026-11-03/manifest.json) and
[raw instance index](evidence/2026-11-03/instances.json) expose the tested
versions, plan IDs, statuses, verdicts and operator-summary distinctions.

This checkout does **not yet contain the tested private backend revision or
complete runner/fixture tooling**. These instructions document that baseline;
they do not assert that this public source already reproduces it. Runtime
reproduction requires a matching build and tooling or a later aligned public
release, as explained in the guide. Existing historical reports remain historical.

The read-only provenance checker is usable here with an independently built
upstream checkout: `python3 conformance/verify_suite.py --source /path/to/suite`.
It runs no conformance modules and does not require private Clavex code.
