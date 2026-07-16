# Cloud credential federation for Terraform (AWS / Azure / GCP)

Clavex can act as the OIDC identity provider that AWS, Azure, and Google
Cloud already support natively for short-lived, federated credentials —
without Clavex ever calling AWS STS, Azure AD, or GCP IAM Credentials
itself. This is the same architecture as "GitHub Actions OIDC to cloud":

```
Terraform run
   │
   ├─► Clavex agent-token issuance (short-lived, signed OIDC id_token,
   │    aud = the cloud's expected audience)
   │
   └─► aws / azurerm / google Terraform provider's OWN native OIDC
        federation (AssumeRoleWithWebIdentity / federated credential /
        Workload Identity Federation), using Clavex's id_token as input
        │
        └─► short-lived cloud credentials (AWS temp keys, Azure AD token,
             GCP access token) — issued by the cloud, never by Clavex
```

Clavex's role is strictly: **issue a bounded, revocable, short-lived,
correctly-audienced id_token.** It never holds, proxies, or requests cloud
credentials — no AWS/Azure/GCP SDK dependency, no per-org role ARNs to
manage, no blast radius if Clavex itself were compromised (it cannot mint
cloud credentials directly, only tokens the cloud's own trust policy
independently evaluates).

## The building block: Agent Tokens

Cloud federation reuses the existing **Agent Token** primitive
(`internal/handler/agent_token.go`) rather than introducing a new machine
identity concept — a CI/CD job is treated the same as an AI agent: a
bounded, revocable, human-delegated credential. Key properties that make it
suitable:

- Signed with the **same JWKS** used for OIDC id_tokens
  (`/{org_slug}/.well-known/jwks.json`) — publicly verifiable by any cloud.
- `sub` = the delegating human user's ID; `agent_id`/`agent_name` identify
  the workload (e.g. `"terraform-prod"`) for audit and for cloud-side trust
  condition matching.
- `aud` (the `audience` field/parameter) is configurable per-request,
  restricted to a per-org allowlist — see "Approving audiences" below.
- Short TTL: pass `ttl_seconds` (recommend 300–900s / 5-15 min); mint a
  fresh token on every CI run rather than reusing one.
- Independently revocable (`DELETE /agent-tokens/:id`) without touching the
  delegating user's session.

## Approving audiences (one-time, per org)

Before any token can be issued with a non-default `audience`, the target
value must be present in the org's allowlist:

```
PUT /api/v1/organizations/:id/agent-token-audiences
{ "allowed_audiences": ["sts.amazonaws.com"] }
```

(superadmin path; org admins with the `security` permission can use the
equivalent org-scoped path `PUT /api/v1/organizations/:org_id/agent-token-
audiences` under their own JWT). Empty allowlist (default) means agent
tokens may only ever be audienced to the issuer — today's behaviour,
unchanged.

## AWS: IAM OIDC Identity Provider + AssumeRoleWithWebIdentity

One-time AWS-side setup:
1. IAM → Identity providers → Add provider → OIDC, with:
   - Provider URL: `https://<org_slug>.<your-domain>` (Clavex's issuer for
     that org — same value used as `issuer` in OIDC discovery)
   - Audience: `sts.amazonaws.com`
2. Create an IAM role with a trust policy conditioning on the token's
   claims, e.g. restricting by `agent_id`:
   ```json
   {
     "Effect": "Allow",
     "Principal": { "Federated": "arn:aws:iam::<account>:oidc-provider/<org_slug>.<your-domain>" },
     "Action": "sts:AssumeRoleWithWebIdentity",
     "Condition": {
       "StringEquals": { "<org_slug>.<your-domain>:aud": "sts.amazonaws.com" },
       "StringLike":   { "<org_slug>.<your-domain>:sub": "*" }
     }
   }
   ```
   (Clavex embeds `agent_id`/`agent_name`/`delegated_by`/`scope` as custom
   claims — AWS trust policy conditions can match on `aud`/`sub` today;
   matching on custom claims requires the newer AWS OIDC claim-condition
   support, check current AWS documentation for availability in your
   partition.)
3. Approve `sts.amazonaws.com` in the org's agent-token audience allowlist
   (see above).

Terraform: see
[`examples/resources/clavex_agent_token/resource_aws_federation.tf`](../terraform-provider/examples/resources/clavex_agent_token/resource_aws_federation.tf)
in the Terraform provider repo — mint a `clavex_agent_token` with
`audience = "sts.amazonaws.com"` and wire its `token` output into the `aws`
provider's `assume_role_with_web_identity` block.

## Azure: Federated Identity Credential

One-time Azure-side setup (on an App Registration):
1. Certificates & secrets → Federated credentials → Add credential →
   "Other issuer".
2. Issuer: `https://<org_slug>.<your-domain>`.
3. Subject identifier: match Clavex's `sub` claim (the delegating user's
   UUID) or use a custom claim-mapping policy if your tenant supports it.
4. Audience: `api://AzureADTokenExchange` (Azure's fixed expected value for
   workload identity federation).

Terraform: mint a `clavex_agent_token` with
`audience = "api://AzureADTokenExchange"` and set `ARM_OIDC_TOKEN` (or use
the azurerm provider's `use_oidc = true` + `oidc_token` argument) to its
`token` output.

## GCP: Workload Identity Federation

One-time GCP-side setup:
1. IAM → Workload Identity Federation → create a pool + OIDC provider:
   - Issuer (issuer URI): `https://<org_slug>.<your-domain>`.
   - Audience: the pool provider's full resource name (GCP generates this,
     e.g. `//iam.googleapis.com/projects/.../workloadIdentityPools/.../providers/...`),
     or a custom audience string if configured.
   - Attribute mapping: e.g. `google.subject = assertion.sub`,
     `attribute.agent_id = assertion.agent_id`.
2. Grant the mapped identity (`principal://...` or
   `principalSet://...`) the target service account's
   `roles/iam.workloadIdentityUser`, or bind it directly to project IAM
   roles.

Terraform: mint a `clavex_agent_token` with `audience` set to the pool
provider's audience string, then use the google provider's
`external_account` credential type (`credential_source` pointing at a file
or command that outputs the token) — see the
[Google provider docs on Workload Identity Federation](https://registry.terraform.io/providers/hashicorp/google/latest/docs/guides/provider_reference#authentication)
for the exact `external_account` JSON shape.

## Security notes

- Always set a short `ttl_seconds` (5-15 min) and mint fresh per CI run —
  do not persist/reuse an agent token as a long-lived cloud credential
  substitute.
- Revoke immediately on suspected compromise: `DELETE
  /api/v1/organizations/:org_id/agent-tokens/:id` invalidates the token
  independently of the delegating user's own session.
- Scope the delegating human user's own permissions tightly — the agent
  token's effective permissions in Clavex are always a subset of the
  delegating user's (`scope` narrowing), but the actual cloud IAM
  role/permissions are entirely controlled by the cloud-side trust policy,
  which Clavex has no visibility into or control over.
