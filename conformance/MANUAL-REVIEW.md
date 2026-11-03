# Screenshots and local manual reviews

This workflow attaches evidence to an **individual suite instance**, then records
an operator decision locally. It never sets an upstream verdict to PASSED.
A different execution of the same module requires its own review.

Use the same suite URL, authentication and CA as the runner:

```sh
export SUITE_URL=https://localhost.emobix.co.uk:8443
export SUITE_CA_FILE="$PWD/conformance/.local/tls/ca.pem"
export CONFORMANCE_REVIEWER='your name or stable reviewer identifier'
# If the suite requires authentication, set SUITE_TOKEN in your shell too.
```

## Inspect and upload evidence for existing instances

Copy the **instance ID** from the suite log page (the `log=` parameter), not the
plan ID or module name:

```sh
./conformance/review-test.sh INSTANCE_ID --inspect
```

The command displays the module, plan, current result/status, pending placeholder
IDs, image hashes and the suite upload-page link. Open that page, read what each
screenshot must show, and inspect the actual screen. Upload through the suite UI
or attach an existing PNG with an explicit placeholder:

```sh
./conformance/review-test.sh INSTANCE_ID \
  --upload /path/to/the-matching-screenshot.png --placeholder PLACEHOLDER_ID
```

Use an existing screenshot only if its instance and the requested interaction
are unambiguous. Files named `/tmp/clavex-INSTANCEPREFIX-iN-before.png` or
`-after.png` are diagnostic captures; a prefix/name alone is not proof that the
image shows the required step. Otherwise retry just that module with capture
and upload enabled. Do not attach a screenshot of a later execution to an older
instance.

The upload uses the official image-placeholder API. The suite normally sets
REVIEW and can finish a still-waiting test once all placeholders are filled.
Uploading to an already interrupted instance does not claim its execution became
FINISHED. This helper refuses uploads to FAILED/SKIPPED instances because the
suite's image API could replace their result with REVIEW.

## Capture and upload during future executions

```sh
make conformance-run-tests ARGS="--plan EXACT_PLAN_ID --module EXACT_MODULE_NAME --rerun --upload-screenshots"
```

`--module` is a substring filter: check its selection before retrying. This command
starts new test instances; it does not repair the old ones.

With `--upload-screenshots`, the runner takes a real current-browser screenshot
when there is a single pending image placeholder, and attaches it using the
suite API. It captures before submitting a login form when that screen is the
pending evidence, and avoids another login after filling the placeholder. It
does not upload an empty/browser-error page, assign one image to multiple
simultaneous requests, or infer that the captured screen is correct. Ambiguous
placeholders require explicit upload/selection. Without this flag existing
execution behaviour is preserved.

Captures and provenance metadata are stored under
`conformance/.local/evidence/SUITE_HASH/INSTANCE_ID/`. Metadata contains the
capture timestamp, instance, placeholder, image SHA-256 and status/result before
upload; it does not contain the browser URL or authentication tokens. These
files and the registry are ignored by Git. Screenshots can still show test-user
information: review them before deliberately sharing an evidence package.

## Record your decision

After examining the image attached in the suite and the expected behaviour:

```sh
./conformance/review-test.sh INSTANCE_ID --approve \
  --note "Expected error page shown; screenshot checked against the test instructions."
```

For incorrect behaviour:

```sh
./conformance/review-test.sh INSTANCE_ID --reject \
  --note "The expected second login prompt is missing."
```

`--reviewer NAME` can replace `CONFORMANCE_REVIEWER`. A reviewer and explanatory
note are mandatory. Approval requires uploaded images, no unfilled screenshot
placeholders, and no FAILED/SKIPPED verdict. The instance must be stopped, or
`WAITING / REVIEW` with all screenshots uploaded: some suite modules retain that
state after receiving their evidence. A local approval does not finish the
instance or change its official state. This is your
assessment, not automatic visual validation. For non-image manual operations,
such as key rotation, complete the required operation/test first; this screenshot
registry does not bypass it.

Decisions append to `conformance/.local/manual-reviews.jsonl` with reviewer,
UTC timestamp, note, suite URL, instance/module/plan, original status/result and
image hashes. A correction appends another decision for the same instance; the
latest one is effective and older records remain. Nothing in this file changes
the suite database. Keep a private backup of this registry and the evidence.

```sh
./conformance/review-test.sh --list
```

## Refresh the report

```sh
make conformance-status
# Or regenerate the full report and its existing automatic-result badges:
conformance/.venv/bin/python conformance/update-conformance-md.py \
  --suite-url "$SUITE_URL"
```

Both report paths include a separate **Local manual verification** section,
linked to the current instances. A fresh read checks that the suite, instance,
plan/module, status/result and image hashes still match the saved decision.
Changed evidence is `stale`; unavailable evidence is `unverified`. Neither is an
approval. Reviews of older instances are retained locally but are not applied to
the latest execution. The full generator accepts `--review-registry PATH` for an
explicitly supplied registry; its default is the local file above.

Official Passed/Review/Failed/Skipped counts and automatic pass-rate badges stay
unchanged by local decisions. Manual approvals/rejections appear separately with
the reviewer and note. The report does not automatically publish anything; check
reviewer identifiers/notes before committing or sharing the generated report.
For an official submission, preserve the suite export with attached evidence
and meet the selected profile's requirements. Local approval is not certification.
