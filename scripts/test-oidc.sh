#!/usr/bin/env bash
# scripts/test-oidc.sh — end-to-end OIDC smoke test
#
# Prerequisites:
#   - clavex running on localhost:8080
#   - make seed ran (or manual org+user creation)
#   - jq installed (brew install jq / apt install jq)
#
# Usage:
#   bash scripts/test-oidc.sh [ORG_SLUG] [EMAIL] [PASSWORD] [CLIENT_ID:CLIENT_SECRET]
#
set -euo pipefail

ORG="${1:-demo}"
EMAIL="${2:-admin@demo.local}"
PASSWORD="${3:-Admin1234!}"
CC_CREDS="${4:-}"  # optional CLIENT_ID:CLIENT_SECRET for client_credentials test
BASE="http://localhost:8080"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
step() { echo -e "\n${CYAN}── $1${NC}"; }

require_jq() {
  command -v jq >/dev/null 2>&1 || { echo "error: jq is required (apt install jq)"; exit 1; }
}

require_jq

# ── 1. Healthcheck ────────────────────────────────────────────────────────────
step "1. Healthcheck"
STATUS=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE}/healthz")
[ "$STATUS" = "200" ] && pass "GET /healthz → 200" || fail "healthz returned $STATUS"

# ── 2. OIDC Discovery ─────────────────────────────────────────────────────────
step "2. OIDC Discovery"
DISCO=$(curl -sf "${BASE}/${ORG}/.well-known/openid-configuration")
ISSUER=$(echo "$DISCO" | jq -r '.issuer')
TOKEN_EP=$(echo "$DISCO" | jq -r '.token_endpoint')
USERINFO_EP=$(echo "$DISCO" | jq -r '.userinfo_endpoint')
JWKS_URI=$(echo "$DISCO" | jq -r '.jwks_uri')
pass "issuer = $ISSUER"
pass "token_endpoint = $TOKEN_EP"

# ── 3. JWKS ───────────────────────────────────────────────────────────────────
step "3. JWKS"
JWKS=$(curl -sf "${JWKS_URI}")
KID=$(echo "$JWKS" | jq -r '.keys[0].kid')
[ -n "$KID" ] && pass "kid = $KID" || fail "no kid in JWKS"

# ── 4. Admin console login ────────────────────────────────────────────────────
step "4. Admin login (POST /api/v1/auth/login)"
LOGIN_RESP=$(curl -sf -X POST "${BASE}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG}\",\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}")
ADMIN_TOKEN=$(echo "$LOGIN_RESP" | jq -r '.token')
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] \
  && pass "admin JWT received (${#ADMIN_TOKEN} chars)" \
  || fail "admin login failed: $LOGIN_RESP"

# ── 5. List organizations (admin API) ─────────────────────────────────────────
step "5. List organizations"
ORGS=$(curl -sf "${BASE}/api/v1/organizations" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}")
ORG_COUNT=$(echo "$ORGS" | jq '. | length' 2>/dev/null || echo "0")
pass "organizations count = $ORG_COUNT"

# ── 6. client_credentials grant ──────────────────────────────────────────────
step "6. client_credentials grant"
if [ -n "$CC_CREDS" ]; then
  CC_CLIENT_ID="${CC_CREDS%%:*}"
  CC_SECRET="${CC_CREDS#*:}"
  CC_RESP=$(curl -sf -X POST "${BASE}/${ORG}/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=${CC_CLIENT_ID}" \
    -d "client_secret=${CC_SECRET}" \
    -d "scope=openid" 2>&1) || true
  CC_AT=$(echo "$CC_RESP" | jq -r '.access_token // empty' 2>/dev/null || true)
  if [ -n "$CC_AT" ]; then
    pass "client_credentials access_token received (${#CC_AT} chars)"
  else
    fail "client_credentials token request failed: $CC_RESP"
  fi
else
  CLIENTS=$(curl -sf "${BASE}/api/v1/organizations/$(echo "$ORGS" | jq -r '.[0].id')/clients" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo "[]")
  CLIENT_COUNT=$(echo "$CLIENTS" | jq '. | length' 2>/dev/null || echo "0")
  if [ "$CLIENT_COUNT" -gt "0" ]; then
    echo "  (pass CLIENT_ID:CLIENT_SECRET as 4th arg to test client_credentials)"
  else
    echo "  (no clients registered — skipping)"
  fi
fi

# ── 7. Authorization code + PKCE — generate URL ───────────────────────────────
step "7. Authorization code + PKCE — generate authorize URL"
# Generate a PKCE code_verifier (43-128 unreserved ASCII chars)
CODE_VERIFIER=$(openssl rand -base64 48 | tr -d '=+/' | head -c 64)
# code_challenge = BASE64URL(SHA256(verifier))
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | \
  openssl dgst -sha256 -binary | \
  openssl base64 | tr '+/' '-_' | tr -d '=')

STATE=$(openssl rand -hex 8)
REDIRECT_URI="http://localhost:5173/callback"

AUTH_URL="${BASE}/${ORG}/authorize?\
response_type=code\
&client_id=demo-spa\
&redirect_uri=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$REDIRECT_URI")\
&scope=openid+profile+email+offline_access\
&state=${STATE}\
&code_challenge=${CODE_CHALLENGE}\
&code_challenge_method=S256"

pass "Authorize URL generated"
echo ""
echo "  Open this URL in your browser to test the full login flow:"
echo "  ${AUTH_URL}" | fold -s -w 100
echo ""
echo "  After login, extract 'code' from the redirect URL and run:"
echo "  CODE=<code_from_url>"
echo "  curl -s -X POST ${TOKEN_EP} \\"
echo "    -d 'grant_type=authorization_code' \\"
echo "    -d \"code=\$CODE\" \\"
echo "    -d 'redirect_uri=${REDIRECT_URI}' \\"
echo "    -d 'client_id=demo-spa' \\"
echo "    -d \"code_verifier=${CODE_VERIFIER}\" | jq"
echo ""

# ── 8. Summary ───────────────────────────────────────────────────────────────
step "Summary"
echo -e "${GREEN}All automated checks passed.${NC}"
echo ""
echo "  Server   : ${BASE}"
echo "  Org      : ${ORG}"
echo "  Issuer   : ${ISSUER}"
echo "  ADMIN JWT: ${ADMIN_TOKEN:0:40}..."
