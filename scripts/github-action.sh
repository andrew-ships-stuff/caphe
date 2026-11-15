#!/usr/bin/env bash
set -euo pipefail

required=(CAPHE_ACTION_PATH CAPHE_BASE_SHA CAPHE_HEAD_SHA CAPHE_REPOSITORY CAPHE_PR GITHUB_WORKSPACE GITHUB_OUTPUT GITHUB_STEP_SUMMARY RUNNER_TEMP)
for name in "${required[@]}"; do [[ -n "${!name:-}" ]] || { echo "$name is required" >&2; exit 2; }; done
[[ "$CAPHE_BASE_SHA" =~ ^[0-9a-f]{40,64}$ && "$CAPHE_HEAD_SHA" =~ ^[0-9a-f]{40,64}$ ]] || { echo "base/head SHA is invalid" >&2; exit 2; }
[[ "$CAPHE_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "$CAPHE_PR" =~ ^[1-9][0-9]*$ ]] || { echo "repository or PR identity is invalid" >&2; exit 2; }

action_state=$(mktemp -d "$RUNNER_TEMP/caphe-action.XXXXXX")
base_tree="$action_state/base"
cleanup() {
  if [[ -d "$base_tree" ]]; then git -C "$GITHUB_WORKSPACE" worktree remove --force "$base_tree" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT INT TERM

if [[ -n "${CAPHE_BINARY:-}" ]]; then
  caphe_binary="$CAPHE_BINARY"
elif [[ "${CAPHE_VERSION:-source}" == source ]]; then
  caphe_binary="$action_state/caphe"
  go -C "$CAPHE_ACTION_PATH" build -trimpath -o "$caphe_binary" ./cmd/caphe
else
  install_dir="$action_state/bin"
  CAPHE_VERSION="$CAPHE_VERSION" CAPHE_INSTALL_DIR="$install_dir" sh "$CAPHE_ACTION_PATH/scripts/install.sh"
  caphe_binary="$install_dir/caphe"
fi
[[ -x "$caphe_binary" ]] || { echo "Caphe binary is not executable" >&2; exit 2; }

tool_bin="$action_state/tools"
caphe_tools="poutine"
if [[ "${CAPHE_AI:-false}" == true && "${CAPHE_AI_SERVE:-false}" == true ]]; then caphe_tools="poutine,llama.cpp"; fi
CAPHE_TOOL_BIN="$tool_bin" bash "$CAPHE_ACTION_PATH/scripts/install-tools.sh" --bin-dir "$tool_bin" --tools "$caphe_tools"
export PATH="$tool_bin:$PATH"
export CAPHE_TOOL_BIN="$tool_bin"

workflow="$CAPHE_WORKFLOW"
[[ -f "$workflow" || "$workflow" == caphe:* ]] || { echo "workflow not found: $workflow" >&2; exit 2; }

git -C "$GITHUB_WORKSPACE" worktree add --detach "$base_tree" "$CAPHE_BASE_SHA"
base_state="$action_state/base-state"
head_state="$action_state/head-state"
base_report="$action_state/base-report.json"
head_report="$action_state/head-report.json"
review="$GITHUB_WORKSPACE/caphe-pr-review.json"
summary="$GITHUB_WORKSPACE/caphe-pr-summary.md"
sarif="$GITHUB_WORKSPACE/caphe-pr.sarif"

"$caphe_binary" scan "$base_tree" --workflow "$workflow" --data-dir "$base_state" --json
"$caphe_binary" report --format json --output "$base_report" --data-dir "$base_state"
"$caphe_binary" scan "$GITHUB_WORKSPACE" --workflow "$workflow" --data-dir "$head_state" --json
"$caphe_binary" report --format json --output "$head_report" --data-dir "$head_state"
"$caphe_binary" hardware inspect --data-dir "$head_state" --json > "$action_state/hardware.json"
"$caphe_binary" ai recommend --data-dir "$head_state" --json > "$action_state/model-recommendation.json"

args=(github analyze --base-report "$base_report" --head-report "$head_report" --base-sha "$CAPHE_BASE_SHA" --head-sha "$CAPHE_HEAD_SHA" --repository "$CAPHE_REPOSITORY" --pr "$CAPHE_PR" --output "$review" --summary-output "$summary" --sarif-output "$sarif" --severity-threshold "${CAPHE_SEVERITY:-high}" --max-comments "${CAPHE_MAX_COMMENTS:-10}" --json)
if [[ "${CAPHE_FAIL_ON_NEW:-true}" == true ]]; then args+=(--fail-on-new); fi
if [[ "${CAPHE_AI:-false}" == true ]]; then
  args+=(--ai --ai-model "${CAPHE_AI_MODEL:-}" --ai-model-digest "${CAPHE_AI_MODEL_DIGEST:-}" --max-model-calls "${CAPHE_MAX_MODEL_CALLS:-3}" --max-input-tokens "${CAPHE_MAX_INPUT_TOKENS:-2048}" --max-output-tokens "${CAPHE_MAX_OUTPUT_TOKENS:-256}" --max-inference-time "${CAPHE_MAX_INFERENCE_TIME:-5m}")
  if [[ "${CAPHE_AI_SERVE:-false}" == true ]]; then
    args+=(--ai-serve --ai-model-url "${CAPHE_AI_MODEL_URL:-}" --ai-threads "${CAPHE_AI_THREADS:-0}")
    if [[ -n "${CAPHE_AI_LLAMA_SERVER:-}" ]]; then args+=(--ai-llama-server "${CAPHE_AI_LLAMA_SERVER}"); fi
  else
    args+=(--ai-endpoint "${CAPHE_AI_ENDPOINT:-http://127.0.0.1:8080}")
  fi
fi
set +e
"$caphe_binary" "${args[@]}"
policy_exit=$?
set -e

[[ -f "$review" && -f "$summary" && -f "$sarif" ]] || { echo "Caphe did not produce required PR artifacts" >&2; exit 1; }
"$caphe_binary" github validate "$review" --repository "$CAPHE_REPOSITORY" --pr "$CAPHE_PR" --base-sha "$CAPHE_BASE_SHA" --head-sha "$CAPHE_HEAD_SHA" --max-comments "${CAPHE_MAX_COMMENTS:-10}" --json
"$caphe_binary" github annotations "$review" --max-comments "${CAPHE_MAX_COMMENTS:-10}"
cat "$summary" >> "$GITHUB_STEP_SUMMARY"
{
  echo "review-artifact=$review"
  echo "sarif=$sarif"
  echo "summary=$summary"
  if [[ $policy_exit -eq 0 ]]; then echo "policy-status=pass"; else echo "policy-status=fail"; fi
} >> "$GITHUB_OUTPUT"
exit "$policy_exit"
