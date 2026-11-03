# Wallet credential/account binding

Implementation checkpoint: 29 October 2026, block 1 of the remaining wallet plan.
Changes are local in the private and public worktrees, not deployed. This is an
account binding control, not an eIDAS, EHDS, OIDC or wallet certification claim.

## Authentication decision

A valid issuer signature and holder proof do not, by themselves, identify the
local account named in a CIBA request. A linked wallet presentation now needs:

- A pending, unexpired presentation and CIBA request in the same organisation.
- An active organisation, target user and requesting OIDC client.
- Verified holder possession, nonce/audience or mdoc device/session binding.
- An account association under one of the explicit rules below.

For local SD-JWT credentials, the signed issuer must exactly equal the configured
base URL plus the organisation slug, the signature must verify with the local
issuer key, and the signed `sub` must equal the target user's UUID. Missing `sub`
is denied. Identity metadata comes from the verified issuer JWT, not disclosure
overrides. Disclosures that overwrite existing or reserved claims are rejected.

For external credentials, issuer trust remains mandatory even when the generic
verifier's conformance mode permits an unknown issuer. An exact identity profile
and an active, explicitly registered account link are also required. No matching
by email/name, first presentation or equality of external `sub` with a local UUID.

Presentation completion and CIBA approval commit in one PostgreSQL transaction.
User, client, organisation and link locks order the decision against concurrent
disable/revoke operations. Conditional updates enforce pending state, target user
and wall-clock expiry. A database failure rolls back both transitions. Concurrent
responses cannot both approve; a busy lock can return 503 and may be retried.

The separate wallet step-up endpoint retains its local-issuer-only scope. It now
requires a signed subject, active tenant/account, a recent signed issue time and
the same holder binding. Its request uses the Final DCQL credentials array and
the prefixed client ID as the KB-JWT audience. A Redis compare-and-set transition
checks subject context, expiry and current pending state without extending TTL.
A late failure cannot overwrite completion. PostgreSQL eligibility locks and
Redis consumption are not a distributed transaction; a commit/notification
failure can leave the challenge completed without an SSF notification. SSF
delivery remains the existing best-effort asynchronous implementation.

## External identity configuration

Migration **185** adds `identity.wallet_identity_links` and a composite foreign
key to enforce organisation/user scope. The active identity tuple is unique per
organisation; revocation retains a tombstone. Existing IdP links, users and CIBA
records are not migrated into wallet links. Apply the earlier pending migrations
183–184 as well through the normal migration process when deploying the build.

Organisation settings accept `wallet_identity_profiles`, for example:

```json
{
  "wallet_identity_profiles": [{
    "format": "dc+sd-jwt",
    "issuer": "https://issuer.example",
    "credential_type": "https://issuer.example/credentials/identity",
    "claim_path": ["stable_identifier"]
  }]
}
```

This is a synthetic example, not an IT-Wallet or national PID profile. The
operator must verify which authoritative, stable claim is available and may be
used for the deployment. The claim must be disclosed when presenting. Identifiers
are exact, case-sensitive strings; missing values and duplicate profile selectors
are denied. Mutable/demographic selectors such as email, names and birth date are
rejected. The selector restrictions are safeguards, not proof that another field
is unique, stable, legally usable or correctly reviewed.

For `mso_mdoc`, select `[namespace, element]`; the issuer selector is
`x509-spki-sha256:<hex SHA-256 of DS certificate SubjectPublicKeyInfo>`. A tenant
IACA trust root permitting the doctype is still necessary. DS key rotation needs
explicit profile/link review; certificate renewal with the same key preserves
this identifier. No automatic trust or account migration is performed.

## Administrative registration

An authenticated organisation administrator (or super-admin) with `users:write`
can call:

`POST /api/v1/organizations/{org_id}/users/{user_id}/wallet-identities`

```json
{
  "format": "dc+sd-jwt",
  "issuer": "https://issuer.example",
  "credential_type": "https://issuer.example/credentials/identity",
  "claim_path": ["stable_identifier"],
  "verified_identifier": "synthetic-person-123",
  "administratively_reviewed": true
}
```

The profile must already be configured exactly for that tenant. The administrator
must independently establish the person's relationship to the target account;
the boolean records an explicit administrative assertion, not automated identity
proofing or an assurance level. There is no self-enrolment or wallet-driven
account creation. The actor must be an active user; its ID and creation time are
recorded. These are API endpoints; no new administration UI is included.

`GET` on that path (`users:read`) returns metadata without the identifier or
digest. `DELETE .../wallet-identities/{link_id}` (`users:write`) revokes the link.
Revocation blocks subsequent binding decisions; it does not revoke an issuer's
credential or retroactively cancel previously approved CIBA requests/tokens.

The registry stores a SHA-256 digest namespaced by organisation, issuer, format,
credential type and claim path. This avoids storing the raw identifier in the
registry, but remains pseudonymous personal data and is susceptible to guessing
for low-entropy identifiers. Existing verified VP claim storage can still contain
disclosed personal data. Retention, access controls and the operator's disclosure
policy therefore still apply; no anonymisation or GDPR compliance is claimed.

## Verification and remaining work

Regression tests exercise local and external SD-JWT binding, mdoc namespace/key
binding, missing links and revocation, another account, absent subject, bearer
presentations, unknown issuer despite conformance mode, inactive users/clients,
expiry, database tenant constraints, permission checks, transactional rollback,
concurrent approval and Redis challenge consumption. They use synthetic keys,
accounts and isolated PostgreSQL/Redis services.

Status/revocation checking for credentials, long-running deferred refresh and
multiple DCQL credentials remain separate planned blocks. External OpenID plans
and actual wallet applications have not been rerun for this checkpoint. Passing
repository tests does not establish real-wallet interoperability or official trust.


The later [local status checkpoint](wallet-status-local.md) additionally requires
status by default for CIBA and step-up. External identity registration alone does
not satisfy that requirement: nonlocal declared status still needs the remote
resolver increment. Missing-status compatibility is an explicit weaker policy,
not a valid-status assertion. See that checkpoint for migration 187 and reissuance
considerations for older credentials.
