# DCQL with multiple credentials

Implementation checkpoint: 29 October 2026. The query/envelope semantics are
pinned to [OpenID4VP 1.0 Final, sections 6 and 8](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html).
Local multi-credential tests have passed in both repositories. The external
single-query run is recorded in [the verification report](reviews/WALLET_VERIFICATION_2026-10-29.md);
it does not establish multi-query interoperability with a physical wallet.

The tenant verifier evaluates multiple required queries, mixed SD-JWT/mdoc
formats, `multiple:true` credential instances, required alternative
`credential_sets` and optional sets. Each returned presentation is checked for
its own format, issuer trust, signature, type/claim constraints, holder/device
proof, nonce, audience/transcript and status. Optional or extra alternatives
that are actually returned are also verified; a valid first credential cannot
hide a bad subsequent credential.

The response must be a JSON object mapping known query IDs to nonempty arrays.
Unknown/duplicate IDs, duplicate instances, wrong cardinality, missing required
queries/groups and trailing JSON are rejected. Limits: 32 credential queries,
32 presented instances in total, eight per query, 64 KiB encoded queries,
4 MiB envelopes, 128 claims per query and claim-path depth 16. Query policies
are validated when requests are created and before they are served to wallets.

Each mdoc instance currently contains one document in its DeviceResponse; multiple
instances are represented by separate responses in the query's presentation
array. `trusted_authorities` needs a framework-specific implementation and is
explicitly rejected rather than silently accepted as a trust decision. Existing
per-format constraints and issuer/certificate trust policies still apply.
`claims.values` remains a wallet disclosure hint, not a clinical/authorization
policy engine. No new EHDS assurance is inferred from matching a query.

## Results and account binding

Single-query/single-instance requests preserve their existing flat result.
Multi-query or multi-instance results expose `_clavex_presentations`, an ordered
array containing query ID, instance index, format, issuer, credential type, claims,
credential status and certificate assessment for **each** verified instance.
There is no implicit last-writer-wins merge of names, email, subject or roles.
The admin verifier displays the credentials separately. Integrations consuming
multiple results must select/project fields explicitly; old flat-claim consumers
must not assume one credential's attributes represent the whole set.

CIBA requires every presented credential to bind independently to the requested
account through the existing signed local subject or registered external
identifier. Same wallet, same holder key or same subject string from different
issuers does not establish that relationship. Distinct holder keys are allowed
when independent account evidence agrees. A missing mapping, revoked second
credential, different account or untrusted issuer prevents the atomic approval.
The audit stores per-credential account-binding decisions and status assessments.

The fixed single-credential wallet step-up query keeps its existing strict
single-query parser. This increment extends the configurable OID4VP verifier and
CIBA presentation sessions, without silently expanding a fixed step-up request.
No additional database migration is needed for the namespaced JSON results.
