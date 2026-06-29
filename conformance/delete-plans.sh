#!/usr/bin/env bash
# conformance/delete-plans.sh
#
# Deletes ALL test plans from the running OIDF conformance suite.
#
# Usage:
#   bash conformance/delete-plans.sh
#   make conformance-delete-plans
#
# Online suite:
#   SUITE_URL=https://www.certification.openid.net \
#   SUITE_TOKEN=<your-token> \
#   make conformance-delete-plans

set -euo pipefail

SUITE_URL="${SUITE_URL:-https://localhost.emobix.co.uk:8443}"
SUITE_TOKEN="${SUITE_TOKEN:-}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

CURL_AUTH=()
if [[ -n "${SUITE_TOKEN}" ]]; then
  CURL_AUTH=(-H "Authorization: Bearer ${SUITE_TOKEN}")
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " clavex — OIDF Conformance Suite: deleting all test plans"
echo " Suite: ${SUITE_URL}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

total=0

while true; do
  IDS=$(curl -sk "${CURL_AUTH[@]}" "${SUITE_URL}/api/plan" \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
plans = d.get('data') or (d if isinstance(d, list) else [])
for p in plans:
    pid = p.get('_id') or p.get('id') or ''
    if pid:
        print(pid)
")

  [[ -z "${IDS}" ]] && break

  while IFS= read -r id; do
    alias=$(curl -sk "${CURL_AUTH[@]}" "${SUITE_URL}/api/plan/${id}" \
      | python3 -c "
import json, sys
d = json.load(sys.stdin)
print((d.get('config') or {}).get('alias') or d.get('alias') or d.get('name') or '?')
" 2>/dev/null || echo "?")

    code=$(curl -sk -o /dev/null -w "%{http_code}" -X DELETE \
      "${CURL_AUTH[@]}" "${SUITE_URL}/api/plan/${id}")

    if [[ "${code}" == "204" || "${code}" == "200" ]]; then
      printf "${GREEN}  ✓${NC}  %s  (%s)\n" "${alias}" "${id}"
    else
      printf "${RED}  ✗${NC}  %s  (%s) → HTTP %s\n" "${alias}" "${id}" "${code}"
    fi
    (( total++ )) || true
  done <<< "${IDS}"
done

echo ""
if [[ ${total} -eq 0 ]]; then
  printf "${YELLOW}  →${NC}  No plans found.\n"
else
  printf "${GREEN}  ✓${NC}  Deleted %d plan(s).\n" "${total}"
fi
echo ""
