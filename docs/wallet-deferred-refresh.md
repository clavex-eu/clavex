> Completion checkpoint: [authorization-code and confidential wallets](wallet-authorization-code.md) extends the initial pre-authorized-only implementation below (migrations 190–191).

# Deferred issuance and wallet refresh grants

Implementation checkpoint: 29 October 2026, block 2 of the remaining wallet plan.
Local changes in the private/public worktrees, not deployed. No formal conformance,
eIDAS, EHDS or official wallet trust recognition is inferred from these changes.

## Scope and endpoints

This increment implements refresh for the existing **pre-authorized** deferred
flow, for anonymous wallets and registered public clients. It does not enable
deferred issuance in the authorization-code flow; that combination remains
explicitly rejected. Ordinary OIDC refresh tokens retain their existing lifecycle.
Confidential client authentication and wallet-instance attestation are not added
to these pre-authorized wallet grants. Supplying unsupported authentication is
rejected instead of silently ignoring a secret or assertion. A public `client_id`
is an identifier, not evidence of client identity or a certified wallet.

Both the discovered `/{org_slug}/token` endpoint and the existing
`/{org_slug}/oid4vci/token` endpoint accept:

```text
grant_type=refresh_token&refresh_token=<current-wallet-refresh-token>
```

If the initial exchange included `client_id`, every refresh must include exactly
that value. Organisation membership, active public client and applicable
sender-binding requirements are checked again. Discovery advertises anonymous
pre-authorized token access when the VCI handler is configured. Wallet refresh
tokens use the `vci_rt.` namespace, which cannot collide with the ordinary
base64url OIDC refresh token format. Delegation precedes generic OIDC proof
processing so a DPoP proof is not consumed twice.

## Grant and token lifecycle

The initial pre-authorized exchange atomically consumes the code and creates a
stable grant plus hashed access/refresh token records. The grant snapshots tenant,
offer, user (or explicitly anonymous subject), configuration UUID/VCT, public
client ID and DPoP/mTLS binding. It grants access to one offer/configuration, not
general OIDC access. Unknown clients, changed subjects, cross-tenant users or
missing configurations are denied. No grant is backfilled for existing offers.

- Access tokens last **at most five minutes**, capped by the grant deadline.
- Deferred-enabled grants receive rotating, opaque refresh tokens and a fixed
  **seven-day maximum deadline from the initial token exchange**. Rotation does
  not slide that deadline. Initial issuance must still occur before offer expiry.
- Once the offer is consumed into a deferred transaction, refresh authorizes
  retrieval of that transaction, even if the original offer expires. It never
  changes the offer back to pending or permits another issuance/configuration.
- Non-deferred exchanges do not receive a refresh token. Changing a configuration
  afterward does not silently add deferred rights to the original grant.
- Refresh tokens are stored only as hashes. Spending the current token and
  inserting its replacement/access token commit together under a grant row lock.
  A database failure rolls back all changes, leaving the old refresh unspent.
- Old access tokens remain valid until their own expiry, subject to eligibility
  and revocation checks. Rotation does not overwrite the single hash on the offer
  or extend any previously issued access token.
- Reuse of a spent refresh token, after verifying the original client/sender
  context, revokes the **entire grant family**, including outstanding access
  tokens. Concurrent use has one winner; subsequent use revokes that winner's
  family too. There is no grace period for ambiguous retries.
- Scope escalation, resource/audience changes and RAR additions are rejected.
  A supplied scope must equal the original configuration scope.

For bearer grants, rotation detects reuse; it does not prevent the first use of
a stolen refresh token. Wallet storage and the deployment’s sender-binding policy
remain necessary controls.

Tokens keep their original sender binding. DPoP requires matching key, method/URL,
fresh proof/JTI, the DPoP authorization scheme and `ath` at credential/deferred
resource endpoints. Redis replay protection fails closed; JTI retention covers
the full time window accepted by the shared parser. mTLS requires the same actual
TLS peer certificate on refresh and resource requests. Forwarded certificate
headers do not establish possession. TLS termination deployments must arrange an
appropriate trusted transport rather than forwarding an unverified header.

## Deferred responses and delivery

The initial deferred response and pending polling responses use **202**, with the
same `transaction_id` and a positive `interval` (currently five seconds). A ready
response uses **200** and `credentials`. Failed authorization uses
`credential_request_denied`; expired, foreign or consumed transactions use
`invalid_transaction_id`. Invalid access tokens use 401. Required storage failures
or busy operations can return 503; clients need a new sender proof when retrying.

The deferred transaction deadline is bounded by the original grant deadline.
Initial verified holder keys are retained; refreshing does not supply or replace
the credential holder key. Tenant/user/client/configuration eligibility and grant
authorization are checked again at approval and retrieval. The legacy batch API
rejects deferred configurations and directs callers to the credential endpoint.

Delivery locks the grant and transaction. Recording `delivered_at`, closing refresh
authorization and preparing the response commit before returning the credential.
`delivered_at` is available in administrative deferred records. Concurrent polling
cannot return a completed credential twice. A response encryption failure rolls
back consumption. Pending and completed responses can use new encryption
parameters from an encrypted deferred request; plain requests carrying encryption
parameters are rejected to prevent substitution.

There is **no exactly-once network delivery guarantee**. If a final HTTP response
is lost after commit, the transaction is already consumed. If a refresh response
is lost after rotation, retrying the old refresh revokes the family. Recovery
requires reviewing the recorded issuance/delivery and starting a new authorized
offer; do not automatically reopen a grant or assume an earlier credential was
never received. Credential cancellation/revocation and any replacement policy
need an explicit operator decision. Grant lifetime does not extend the signed
credential's validity period.

## Migration and existing installations

Migration **186** adds wallet grant/token tables, a persistent offer generation
marker, `delivered_at` and one-deferred-transaction-per-offer uniqueness. The
generation marker prevents a deleted/revoked new grant from falling back to the
old offer bearer hash, including when deleting a user cascades its grant records.
No user, license, billing, subscription or ownership data is rewritten.

Before applying to an existing installation, check for historical duplicate
deferred transactions:

```sql
SELECT org_id, offer_id, count(*)
FROM identity.deferred_credentials
GROUP BY org_id, offer_id HAVING count(*) > 1;
```

The migration does not delete or merge duplicates; if present, the unique index
fails and the operator must review them. Prior migrations 183–185 are required.
Legacy offers gain no refresh token or invented grant deadline. Their existing
unexpired bearer access is retained, with scoped delivery controls. New grants
must be issued through the token endpoint.

A deliberate schema downgrade invalidates new-generation offer access hashes
before removing grant tables/markers, so revoked new tokens cannot reappear as
legacy bearer tokens. Existing legacy offer hashes are unaffected. Down/up was
only tested in an isolated database; no cluster migration or rollback is run.
Retention/cleanup of spent token hashes must follow the deployment's data policy;
this increment keeps reuse evidence and does not add a deletion scheduler.

## Verification boundaries

Repository tests use isolated PostgreSQL/Redis, synthetic keys/accounts, and
database-controlled expiry changes instead of waiting five minutes. They cover
expiry and refresh through the discovered endpoint, rotation/reuse/concurrency,
scope/client/tenant separation, DPoP `ath`/replay, mTLS possession, active subject
checks, user deletion without legacy-token resurrection, transactional rollback,
delivery concurrency, transaction isolation and encrypted delivery rollback.

The external OpenID suite and actual IT-Wallet/EUDI apps have **not** been rerun.
The React `useCredentialOffer` helper remains a legacy helper, with no durable
deferred/refresh workflow; these backend changes do not make that SDK a complete
wallet implementation. The later [local status checkpoint](wallet-status-local.md) adds local SD-JWT
revocation checks and a local issued-record guard before delivery. Remote status,
mdoc/certificate and attestation revocation, and multiple-credential DCQL remain
open; this does not establish their full validation.

Normative baseline: [OID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html),
sections 6, 8.3, 9 and 12.3. Local regression results are recorded in
[wallet security hardening](wallet-security-hardening.md).
