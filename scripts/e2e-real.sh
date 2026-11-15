#!/usr/bin/env bash
set -euo pipefail

binary="${1:-./bin/caphe}"
for tool in poutine; do command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required for real E2E" >&2; exit 2; }; done

state_dir=${CAPHE_E2E_STATE_DIR:-$(mktemp -d)}
lock_file=$(mktemp)
report_file=${CAPHE_E2E_REPORT:-$(mktemp)}
mkdir -p "$state_dir"
trap 'rm -f "$lock_file"' EXIT INT TERM

"$binary" tools doctor --json
"$binary" compile caphe:git-security --output "$lock_file" --json
"$binary" validate "$lock_file" --json
"$binary" run "$lock_file" --target . --data-dir "$state_dir" --json
"$binary" report --format sarif --output "$report_file" --data-dir "$state_dir"
python3 -m json.tool "$report_file" >/dev/null
echo "Real E2E completed with poutine and valid SARIF output."
