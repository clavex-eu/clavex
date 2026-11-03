#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${CONFORMANCE_PYTHON:-$script_dir/.venv/bin/python}"
if [[ ! -x "$python_bin" ]]; then python_bin=python3; fi
exec "$python_bin" "$script_dir/review-test.py" "$@"
