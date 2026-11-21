#!/usr/bin/env bash
set -euo pipefail
context=${CAPHE_K8S_CONTEXT:-caphe-local}
namespace=${CAPHE_K8S_NAMESPACE:-caphe-local}
k=(kubectl --context "$context" -n "$namespace")
"${k[@]}" rollout status deployment/caphe-api --timeout=180s
"${k[@]}" rollout status deployment/caphe-worker --timeout=180s
api_ip=$("${k[@]}" get service caphe -o jsonpath='{.spec.clusterIP}')
# Positive control proves the destination is reachable before checking denial.
"${k[@]}" exec deployment/caphe-api -- timeout 5 bash -c "echo > /dev/tcp/$api_ip/8787"
set +e
"${k[@]}" exec deployment/caphe-worker -- timeout 5 bash -c "echo > /dev/tcp/$api_ip/8787"
status=$?
set -e
if [[ "$status" != 124 && "$status" != 1 ]]; then
  echo "Worker network isolation failed (exit $status)" >&2
  exit 1
fi
log=$(mktemp)
"${k[@]}" port-forward --address 127.0.0.1 service/caphe 18787:8787 >"$log" 2>&1 &
forward_pid=$!
cleanup() {
  kill "$forward_pid" 2>/dev/null || true
  wait "$forward_pid" 2>/dev/null || true
  rm -f "$log"
}
trap cleanup EXIT
for ((i=0; i<60; i++)); do
  if grep -q 'Forwarding from 127.0.0.1:18787' "$log" && curl -fsS http://127.0.0.1:18787/healthz >/dev/null; then break; fi
  if ! kill -0 "$forward_pid" 2>/dev/null; then cat "$log"; exit 1; fi
  sleep 1
done
if ! grep -q 'Forwarding from 127.0.0.1:18787' "$log"; then cat "$log"; exit 1; fi
CAPHE_TEST_ENDPOINT=http://127.0.0.1:18787 go test ./tests/deployments -count=1 -v -timeout=10m
