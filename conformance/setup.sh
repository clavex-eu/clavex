#!/usr/bin/env bash
# conformance/setup.sh
#
# Seeds clavex with the org, test user, and OIDC client required by the
# OpenID Connect Conformance Suite.
#
# Prerequisites:
#   - clavex running  (make run  or  docker compose up)
#   - postgres accessible (connection from config.yaml / env vars)
#
# Usage:
#   bash conformance/setup.sh
#   make conformance-setup

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " clavex — conformance seed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd "$REPO_ROOT"

# Auto-select a config file if --config was not already supplied.
# Precedence: config.yaml → config.dev.yaml
if [[ "$*" != *"--config"* ]]; then
  if [[ -f "config.yaml" ]]; then
    set -- "$@" --config config.yaml
  elif [[ -f "config.dev.yaml" ]]; then
    set -- "$@" --config config.dev.yaml
  fi
fi

# Retry up to 5 times with increasing delay — the DB connection (e.g. via
# kubectl port-forward) can drop transiently mid-run.  The seed is idempotent.
max_attempts=5
attempt=1
while true; do
  go run ./cmd/conformance-seed "$@" && break
  exit_code=$?
  if [[ ${attempt} -ge ${max_attempts} ]]; then
    echo "conformance-seed failed after ${max_attempts} attempts (exit ${exit_code})"
    exit "${exit_code}"
  fi
  delay=$(( attempt * 3 ))
  echo "conformance-seed failed (attempt ${attempt}/${max_attempts}) — retrying in ${delay}s…"
  sleep "${delay}"
  (( attempt++ ))
done
