#!/usr/bin/env bash
# conformance/create-plans.sh
#
# Creates all Clavex test plans in the running OIDF conformance suite.
#
# Prerequisites:
#   - make conformance-up      (suite running at https://localhost:8443)
#   - make conformance-setup   (org + client seeded in clavex)
#
# Usage:
#   bash conformance/create-plans.sh
#   make conformance-create-plans

set -euo pipefail

SUITE_URL="${SUITE_URL:-https://localhost:8443}"
SUITE_TOKEN="${SUITE_TOKEN:-}"
DIR="$(cd "$(dirname "$0")" && pwd)"

# Path to the FAPI private keys written by conformance-seed.
# create-plans.sh injects them into FAPI plan configs automatically.
# client  → fapi-private-key.jwk   (conformance-client-fapi)
# client2 → fapi2-private-key.jwk  (conformance-client-fapi-2, distinct keypair)
FAPI_KEY_FILE="${DIR}/fapi-private-key.jwk"
FAPI2_KEY_FILE="${DIR}/fapi2-private-key.jwk"

# colour helpers
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok()   { printf "${GREEN}  ✓${NC}  %s\n" "$*"; }
err()  { printf "${RED}  ✗${NC}  %s\n" "$*"; }
info() { printf "${YELLOW}  →${NC}  %s\n" "$*"; }

# Optional Bearer token header as a proper bash array (safe word-splitting).
CURL_AUTH=()
if [[ -n "${SUITE_TOKEN}" ]]; then
  CURL_AUTH=(-H "Authorization: Bearer ${SUITE_TOKEN}")
fi

# create_plan <planName> <configFile>
#
# The conformance suite API (v24+) requires plan-level variants to be passed
# as a JSON-encoded URL query parameter (?variant=<json>). Module-level variants
# (client_auth_type, response_type, response_mode) must NOT be included — they
# are fixed by the plan's module definitions and the suite rejects duplicates.
#
# The JSON config file may have a "variant" key containing only the plan-level
# variants. This function extracts it, URL-encodes it, and strips it from the
# body before sending, so the body is pure configuration (alias, server, client…).
#
# Optional third argument: "fapi" — if set, the private JWK from
# FAPI_KEY_FILE is injected into client.jwks so the suite can sign
# client_assertion JWTs without manual configuration.
create_plan() {
  local plan_name="$1"
  local config_file="$2"
  local inject_key="${3:-}"

  local alias
  alias=$(python3 -c "import json,sys; print(json.load(open('${config_file}'))['alias'])")

  # Extract plan-level variant (may be empty object {})
  local variant_json
  variant_json=$(python3 -c "
import json,sys
d = json.load(open('${config_file}'))
v = d.get('variant', {})
print(json.dumps(v))
")

  # Build the body without the 'variant' key
  local body
  body=$(python3 -c "
import json,sys
d = json.load(open('${config_file}'))
d.pop('variant', None)
print(json.dumps(d))
")

  # For FAPI plans: inject the distinct private JWKs into client.jwks and
  # client2.jwks so the suite can authenticate as each client without manual
  # key configuration.  Using different keys for client and client2 satisfies
  # the FAPI2 ValidateClientPrivateKeysAreDifferent conformance check.
  if [[ "${inject_key}" == "fapi" ]]; then
    if [[ ! -f "${FAPI_KEY_FILE}" ]]; then
      err "FAPI key file not found: ${FAPI_KEY_FILE}"
      err "Run 'make conformance-setup' first to generate the keypair."
      return 1
    fi
    if [[ ! -f "${FAPI2_KEY_FILE}" ]]; then
      err "FAPI2 key file not found: ${FAPI2_KEY_FILE}"
      err "Run 'make conformance-setup' first to generate the keypair."
      return 1
    fi
    body=$(python3 -c "
import json, sys
body  = json.loads(sys.argv[1])
key   = json.load(open('${FAPI_KEY_FILE}'))
key2  = json.load(open('${FAPI2_KEY_FILE}'))
# client  uses the primary key (conformance-client-fapi)
# client2 uses the secondary key (conformance-client-fapi-2)
# Each is a {\"keys\":[<private_jwk>]} object so the suite can sign
# client_assertion JWTs for both clients independently.
body.setdefault('client', {})['jwks'] = {'keys': [key]}
body.setdefault('client2', {})['jwks'] = {'keys': [key2]}
print(json.dumps(body))
" "${body}")
    info "Injected FAPI keys: client=${FAPI_KEY_FILE} client2=${FAPI2_KEY_FILE}"
  fi

  # URL-encode the variant JSON string
  local variant_enc
  variant_enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "${variant_json}")

  info "Creating ${plan_name} (alias: ${alias}) …"

  local response
  response=$(curl -sk -X POST \
    "${SUITE_URL}/api/plan?planName=${plan_name}&variant=${variant_enc}" \
    -H "Content-Type: application/json" \
    "${CURL_AUTH[@]}" \
    -d "${body}" 2>&1)

  if echo "${response}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['id'])" 2>/dev/null; then
    local plan_id
    plan_id=$(echo "${response}" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
    ok "id=${plan_id}  →  ${SUITE_URL}/plan-detail.html?plan=${plan_id}"
  else
    err "Failed (response below)"
    echo "${response}" | python3 -m json.tool 2>/dev/null || echo "${response}"
    return 1
  fi
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " clavex — OIDF Conformance Suite: creating test plans"
echo " Suite: ${SUITE_URL}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Plan 1: Basic OP (Authorization Code + PKCE + client_secret_basic) ─────────
create_plan \
  "oidcc-basic-certification-test-plan" \
  "${DIR}/oidcc-basic-plan.json"

# ── Plan 2: Basic OP with client_secret_post ────────────────────────────────────
# oidcc-basic-certification-test-plan fixes client_auth_type at the module level
# (client_secret_basic). To test client_secret_post we use oidcc-test-plan which
# exposes client_auth_type as a plan-level variant.
create_plan \
  "oidcc-test-plan" \
  "${DIR}/oidcc-basic-post-plan.json"

# ── Plan 3: Config OP (Discovery / Provider Metadata) ──────────────────────────
create_plan \
  "oidcc-config-certification-test-plan" \
  "${DIR}/oidcc-config-plan.json"

# ── Plan 4: Dynamic OP (RFC 7591 Dynamic Client Registration) ──────────────────
create_plan \
  "oidcc-dynamic-certification-test-plan" \
  "${DIR}/oidcc-dynamic-plan.json"

# ── Plan 5: Form Post OP (response_mode=form_post) ─────────────────────────────
create_plan \
  "oidcc-test-plan" \
  "${DIR}/oidcc-form-post-plan.json"

# ── Plan 6: Hybrid Flow OP (response_type=code id_token) ──────────────────────
create_plan \
  "oidcc-test-plan" \
  "${DIR}/oidcc-hybrid-plan.json"

# ── Plan 10: PAR standalone (Pushed Authorization Requests, RFC 9126) ──────────
create_plan \
  "oidcc-test-plan" \
  "${DIR}/par-test-plan.json"

# ── Plan 7: FAPI 2.0 Baseline — DPoP (private_key_jwt + DPoP sender-constrain) ─
# Prerequisite: conformance-client-fapi must be seeded (make conformance-setup)
# and the suite must be able to reach clavex via HTTPS.
create_plan \
  "fapi2-security-profile-id2-test-plan" \
  "${DIR}/fapi2-baseline-dpop-plan.json" \
  fapi

# ── Plan 8: FAPI 2.0 Baseline — MTLS (private_key_jwt + MTLS sender-constrain) ─
# Low priority: requires mutual-TLS infrastructure. Included for completeness.
create_plan \
  "fapi2-security-profile-id2-test-plan" \
  "${DIR}/fapi2-baseline-mtls-plan.json" \
  fapi

# ── Plan 9: FAPI 2.0 Message Signing — JARM ───────────────────────────────────
# Tests signed authorization responses (JARM/fapi_response_mode=jarm) per FAPI 2.0 MS.
create_plan \
  "fapi2-message-signing-id1-test-plan" \
  "${DIR}/fapi2-message-signing-plan.json" \
  fapi

# ── Plan 11: Token Introspection (RFC 7662) ────────────────────────────────────
# Not an OIDF conformance plan — no suite API entry. Use introspection-test-plan.json
# as a reference spec for manual or script-based smoke tests against /introspect.
info "Plan 11 (Token Introspection) is a local test spec — see conformance/introspection-test-plan.json"

# ── Plan 12: Device Authorization Grant (RFC 8628) ─────────────────────────────
# NOTE: the plan name below must match what the running suite exposes.
# Verify with: curl -sk https://localhost:8443/api/plan/available \
#              | python3 -c "import json,sys; [print(p['planName']) for p in json.load(sys.stdin)]" \
#              | grep -i device
# Known-wrong alias (suite may not include this plan in all builds):
#   oauth2-device-authorization-grant-test-plan
# Use || true so a wrong/missing plan name does not abort the remaining plans.
create_plan \
  "oauth2-device-authorization-grant-test-plan" \
  "${DIR}/device-flow-plan.json" || true

# ── Plan 13: OID4VCI Final (September 2025) Issuer ───────────────────────────
# Tests OID4VCI Final spec issuer compliance: credential_configuration_id,
# proof_types_supported, PS256 signing, vc+sd-jwt format.
# Verify plan name: curl -sk https://localhost:8443/api/plan/available \
#   | python3 -c "import json,sys; [print(p['planName']) for p in json.load(sys.stdin)]" \
#   | grep -i oid4vci
create_plan \
  "oid4vci-1_0-issuer-test-plan" \
  "${DIR}/oid4vci-issuer-plan.json" || true

# ── Plan 13b: OID4VCI Final Issuer — credential_response_encryption variant ──
# Covers tests that only run with vci_credential_encryption=encrypted, e.g.
# oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm.
create_plan \
  "oid4vci-1_0-issuer-test-plan" \
  "${DIR}/oid4vci-issuer-encrypted-plan.json" || true

# ── Plan 14: HAIP 1.0 (High Assurance Interoperability Profile, eIDAS 2.0) ───
# Tests HAIP 1.0 compliance: PS256 mandatory, dc+sd-jwt format, key binding.
# Requires OID4VCI plan passing first.
# Verify plan name: curl -sk https://localhost:8443/api/plan/available \
#   | python3 -c "import json,sys; [print(p['planName']) for p in json.load(sys.stdin)]" \
#   | grep -i haip
create_plan \
  "oid4vci-1_0-issuer-haip-test-plan" \
  "${DIR}/haip-plan.json" || true

# ── Plan 15: OID4VP 1.0 Final Verifier (sd-jwt-vc + url_query + redirect_uri) ─
# Clavex acts as the Verifier; the suite acts as a fake Wallet.
# Protocol: the Verifier (Clavex) calls the Wallet's authorization_endpoint
# with all parameters in the URL query string (request_method=url_query).
# client_id equals the response_uri (redirect_uri scheme); no pre-registered
# OIDC client is required in the Clavex DB.
#
# Manual test procedure:
#   1. Create the plan and start the Happy Flow test module.
#   2. Copy the exposed authorization_endpoint URL from the suite UI.
#   3. Use the Clavex API to initiate a VP session targeting that URL:
#        POST /conformance/wallet/request {"presentation_definition": {...}}
#      → returns {request_uri, nonce}
#   4. Invoke the wallet URL directly (GET with all VP params in query string).
#
# Verify plan name: curl -sk https://localhost:8443/api/plan/available \
#   | python3 -c "import json,sys; [print(p['planName']) for p in json.load(sys.stdin)]" \
#   | grep -i oid4vp
create_plan \
  "oid4vp-1final-verifier-test-plan" \
  "${DIR}/oid4vp-verifier-plan.json" || true

# ── Plan 16: FAPI 2.0 CIBA Poll (backchannel authentication, poll delivery) ───
# Clavex acts as the AS; the suite initiates backchannel auth requests.
# Requires conformance-client-ciba seeded (make conformance-setup).
# Plan-level variant: ciba_mode=poll, client_auth_type=private_key_jwt.
# The FAPI key is injected via the "fapi" flag in create_plan.
# Verify plan name: curl -sk https://localhost:8443/api/plan/available \
#   | python3 -c "import json,sys; [print(p['planName']) for p in json.load(sys.stdin)]" \
#   | grep -i ciba
create_plan \
  "fapi-ciba-id1-test-plan" \
  "${DIR}/fapi2-ciba-poll-plan.json" \
  fapi || true

# ── Plan 17: OID4VCI Final Issuer — pre-authorized code flow (plain) ──────────
# Clavex acts as the Credential Issuer; the suite acts as a wallet using a
# credential offer obtained via the pre-authorized_code grant type.
# client_auth_type=none (anonymous wallet): Clavex pre-auth token endpoint does
# not require client authentication.
# Manual step before running: create a credential offer via the Clavex admin API:
#   POST /api/v1/organizations/<org_id>/oid4vci/offers
#       {"vct":"vct_conformance-identity"}
# then submit the returned openid-credential-offer:// URI to the suite UI.
create_plan \
  "oid4vci-1_0-issuer-test-plan" \
  "${DIR}/oid4vci-issuer-pre-auth-plan.json" || true

# ── Plan 17b: OID4VCI Final Issuer — pre-authorized code + encrypted response ─
create_plan \
  "oid4vci-1_0-issuer-test-plan" \
  "${DIR}/oid4vci-issuer-pre-auth-encrypted-plan.json" || true

# ── Plan 18: OID4VCI Final Issuer — mso_mdoc format (ISO 18013-5 mDL) ────────
# Tests mso_mdoc credential issuance via auth-code flow.
# Prerequisite: make conformance-setup populates the mdoc credential config and
# seeds the IACA CA + DS key pair; trust_anchor_pem is auto-updated in this file.
create_plan \
  "oid4vci-1_0-issuer-test-plan" \
  "${DIR}/oid4vci-issuer-mso-mdoc-plan.json" || true

# ── Plan 18b: OID4VCI Final Issuer — mso_mdoc + encrypted credential response ─
create_plan \
  "oid4vci-1_0-issuer-test-plan" \
  "${DIR}/oid4vci-issuer-mso-mdoc-encrypted-plan.json" || true

# ── Plan 19: OpenID Federation 1.0 — OP conformance ──────────────────────────
# Tests that Clavex publishes a valid Entity Configuration JWT and supports
# federation-aware discovery and client registration.
# Prerequisite: federation.enabled = true in clavex config.
# Verify plan name: curl -sk https://localhost:8443/api/plan/available \
#   | python3 -c "import json,sys; [print(p['planName']) for p in json.load(sys.stdin)]" \
#   | grep -i fed
create_plan \
  "openid-federation-entity-joined-to-test-federation-op-test-plan" \
  "${DIR}/openid-federation-plan.json" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Open the suite UI to run the plans:"
printf "   ${GREEN}%s${NC}\n" "${SUITE_URL}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
