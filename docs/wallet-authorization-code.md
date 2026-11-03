# Wallet authorization-code/deferred and confidential clients

Implementation checkpoint: 29 October 2026. Migrations 190–191 extend the stable
wallet grants introduced by migration 186; these do not modify software licensing
or commercial subscription state. Historical wallet grants remain public/anonymous
with the original deadline and no invented attestation link.

## Authorization code

The discovered tenant OAuth `/token` endpoint recognises authorization codes
that actually authorize a configured deferred credential through a credential
scope or `openid_credential` RAR. Ordinary OIDC requests retain their existing
exchange path. The dedicated `/oid4vci/token` endpoint also accepts the wallet
`authorization_code` grant.

A single transaction consumes the code, checks tenant/client/redirect URI,
expiry, S256 PKCE (including confidential wallets), subject eligibility, configured
client grant types and authorization to the selected credential configuration,
then creates an internal issuance offer, stable grant and initial tokens. The
internal pre-authorized code is random and never exposed. Failed validation does
not consume the code. Reusing a successfully consumed code cannot create a second
grant. Each wallet grant authorizes one configuration; when a code authorizes
more, the wallet selects one authorized configuration using token-request
`authorization_details`. The selection cannot broaden the code's authorization.

Deferred code grants use the existing short access-token / rotating refresh-token
lifecycle, fixed maximum seven-day grant deadline, sender bindings, reuse detection,
one-shot delivery and current eligibility checks. Confidential/public clients
must be registered for `authorization_code` and `refresh_token` when deferred
renewal is needed. Refresh does not enlarge scopes or reopen consumed issuance.

Authorization-code wallet access tokens remain signed JWTs; mixed OpenID and
credential scopes retain an ID token with `at_hash` matching that exact access
token. The JWT contains an internal wallet-grant marker. Expired/revoked/closed
wallet tokens and JWTs whose grant records were deleted cannot fall back to the
legacy generic OIDC credential endpoint and escape the wallet lifecycle. Resource
DPoP checks require the actual token hash (`ath`).

## Client authentication

Wallet pre-authorized/code/refresh token exchanges reuse the registered OIDC
client authentication implementation, with explicit method/tenant checks:

- Public client (`none`) or anonymous pre-authorized wallet.
- `client_secret_basic` and `client_secret_post`, without method mixing.
- `private_key_jwt`, with fresh bounded asymmetric assertion and replay check.
- `tls_client_auth`, using a verified TLS connection, registered certificate
  identity and the same certificate binding during renewal.
- `attest_jwt_client_auth`, using a signed typed attestation and PoP, retaining
  the attested instance-key thumbprint across refresh rotation.

Secrets, assertions and header authentication are no longer silently ignored or
rejected simply because the client is confidential. Invalid authentication is
`401 invalid_client`; unavailable dependencies are `503`. Changing the registered
method cannot downgrade a grant created with stronger authentication. Client,
tenant, user and credential configuration must still be active at the final
transactional decision.

Wallet private-key assertions/attestation PoPs require JTI, iat, exp, approved
asymmetric algorithms and at most a five-minute proof lifetime. Replay-store
failure now fails closed in the shared assertion validator; TTL includes its
accepted clock-skew window. This shared fix also protects ordinary OIDC assertion
authentication. Existing OIDC attestation trust uses the client's registered JWKS;
it is not, by itself, an EUDI wallet-provider trust-list implementation.

Authenticated wallet/client-attestation status pointers are persisted on the grant,
rechecked on resource use and refresh, and copied to deferred/issued records.
This completes their connection to the parent monitoring/cascading mechanism in
[wallet status](wallet-status-remote.md). Refresh must prove the original attested
instance even when another otherwise valid provider attestation exists.

## Verification boundaries

Repository integration tests cover code consumption/PKCE retry, public DPoP/RAR,
confidential refresh/deferred delivery, wrong tenant/secret/method/instance,
assertion replay/store outage, actual TLS certificate binding and deleted-grant
JWT fallback. The external suite has been rerun for selected issuer/verifier cases;
[the verification report](reviews/WALLET_VERIFICATION_2026-10-29.md) preserves
passes, manual review and the remaining issuer failure separately. External
authorization-code/deferred coverage and physical-wallet tests remain open.
No conformance certificate is claimed.
