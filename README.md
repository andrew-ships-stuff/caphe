<p align="center">
  <img src="assets/caphe_logo_640.png" alt="Caphe" width="440" height="174" />
</p>

# Caphe

[![CI](https://github.com/andrew-ships-stuff/caphe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/andrew-ships-stuff/caphe/actions/workflows/ci.yml)
[![End-to-end](https://github.com/andrew-ships-stuff/caphe/actions/workflows/e2e.yml/badge.svg?branch=main)](https://github.com/andrew-ships-stuff/caphe/actions/workflows/e2e.yml)
[![Caphe security analysis](https://github.com/andrew-ships-stuff/caphe/actions/workflows/caphe-pr.yml/badge.svg?event=pull_request)](https://github.com/andrew-ships-stuff/caphe/actions/workflows/caphe-pr.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/andrew-ships-stuff/caphe?logo=go)](https://github.com/andrew-ships-stuff/caphe/blob/main/go.mod)
[![License: MIT](https://img.shields.io/github/license/andrew-ships-stuff/caphe)](https://github.com/andrew-ships-stuff/caphe/blob/main/LICENSE)

Caphe is an evidence-first security audit CLI and self-hosted service. It compiles declarative YAML into a content-addressed workflow lock, executes a fixed DAG of installed security scanners, preserves their raw output, normalizes and correlates findings in SQLite, and emits digest-pinned JSON, SARIF, Markdown, and HTML reports with a deterministic remediation plan.

Security scanners—not an LLM—produce Caphe's potential vulnerability findings. Caphe groups their evidence, surfaces available package fix versions, and generates copyable fix prompts. Optional CPU inference can review scanner results using a small, digest-verified model served by `llama.cpp` on loopback. Model-written explanations, priorities, and deduplication suggestions remain clearly labeled, unverified `hypothesis` output and never control execution or policy.

Caphe runs locally without an LLM, GPU, Docker, Kubernetes, API key, or database server. The same deterministic audit engine can also run behind Caphe's authenticated cluster API using Docker Compose or Helm. Cluster workers currently perform scanner-only audits; optional inference is available in the local CLI and GitHub review flows.

## Quick start

```bash
brew install andrew-ships-stuff/tap/caphe
caphe setup
caphe audit .
```

`caphe setup` is the first-run command: it initializes local state, lets you choose scanners and bounded CPU inference, and offers to install every missing checksum-pinned tool needed by that selection. Caphe automatically discovers its managed tool directory; no shell `PATH` edit is required. Run `caphe setup --install` later to repair a partial installation, or `caphe doctor` to inspect exactly what is available. Missing optional scanners still degrade to explicit `skipped` tasks; Caphe never fabricates replacement findings.

## Current working scope

- Go CLI: `version`, `doctor`, `init`, hardware inspection, tool discovery, workflow validation/compilation/lock validation, scan/run/audit, cluster service and workers, findings, graph queries, reports, and optional AI analysis.
- Real installed-tool adapters for Opengrep, Syft, Grype, Gitleaks, Poutine, OPA, OSV-Scanner, Checkov, and Kubescape. No production mock fallback exists.
- Canonical workflow locks with adapter pinning, bounded timeout/retry policy, security/syntax gate records, and SHA-256 digests.
- Dependency-aware concurrent executor with partial failure, cancellation, raw artifact retention, and execution manifests.
- SQLite findings/evidence store and content-addressed artifact files.
- Native JSON, SARIF 2.1.0, and self-contained HTML reporting: dark dashboard with per-tool cards (tasks merged into their scanner identity), global and per-column filters, paginated findings in a sortable-free clean table (25/50/100/ALL), CSV export, a deterministic deduplicated remediation plan (package@version → fix versions, repeated rule+location occurrences collapsed, tallied advisories with NVD/GitHub/OSV/Opengrep-registry links), per-line copyable agent fix prompts, a copy-all button that falls back to grep-against-the-file instructions when the prompt set is too large to paste, and optional local-LLM dedup **hypothesis** suggestions (never auto-merged; deterministic grouping is authoritative).
- CPU/memory/disk inspection and conservative, explicitly unvalidated model recommendations.
- A loopback-only `llama.cpp` provider. `caphe audit --ai --ai-serve` downloads a digest-verified model, launches a private CPU inference subprocess on an ephemeral loopback port, enforces call/token/time budgets, and stops it after the audit.
- An authenticated cluster API with bounded archive or immutable-Git submissions, renewable worker leases, Docker Compose packaging, and a Helm chart. The current queue uses shared filesystem storage and does not yet claim OIDC, object storage, or exactly-once execution.

See [docs/roadmap.md](docs/roadmap.md) for the exact boundary between implemented and planned functionality.

## Build

Requirements: Go 1.26 or newer for this development snapshot.

```bash
go build -o caphe ./cmd/caphe
go test ./...
go vet ./...
./caphe version
./caphe doctor
```

Scanners are optional per workflow. Install the tools required by the selected workflow and verify them with:

```bash
caphe tools doctor
```

Caphe never silently substitutes generated findings when a scanner is missing. On macOS, Linux, and Windows, install scanner releases from their respective upstream projects: Opengrep, Anchore Syft, Anchore Grype, Gitleaks, Poutine, OPA, OSV-Scanner, Checkov, and Kubescape. Pin versions in CI and preserve the execution manifest that records detected versions.

For an easily removable local toolchain, `make install` builds and installs Caphe and calls `install-tools` to install the checksum-pinned managed tools. The standalone tool targets also work; use `TOOLS=` to install only a subset:

```bash
make install
make install-tools
make tools-install TOOLS=syft,grype,gitleaks
caphe tools doctor
```

The default managed set is Poutine, Syft, Grype, Gitleaks, `llama.cpp`, and the repository companion actionlint. Opengrep must be installed separately. The default cache is `${XDG_CACHE_HOME:-$HOME/.cache}/caphe`; set `CAPHE_CACHE` or pass `scripts/install-tools.sh --bin-dir PATH` to choose another location. Add its `bin` directory to `PATH` to invoke Caphe. Removing that dedicated directory removes the managed binaries. Caphe does not install system packages or request elevated privileges. Use `make build` to build only Caphe without downloading tools.

Installing Grype does not refresh or repair its vulnerability database. If an audit skips Grype because its database is stale, run `grype db update` using the managed binary (by default, `${XDG_CACHE_HOME:-$HOME/.cache}/caphe/bin/grype`). If database corruption persists, `grype db delete` followed by `grype db update` rebuilds the local database; the update requires network access. A repeated hydration/migration failure may require an upstream Grype fix and a separately reviewed version/checksum pin update. Do not disable database age validation to make the scan pass.

Homebrew users can install commonly used tools independently:

```bash
brew install poutine syft grype gitleaks opa osv-scanner checkov kubescape actionlint
```

`scripts/install-tools.sh` only manages tools with reviewed version and checksum pins. Install OPA, OSV-Scanner, Checkov, and Kubescape independently until equivalent pins are added; Caphe will discover them from `PATH`. actionlint remains a repository/CI companion rather than a workflow adapter.

## Homebrew installation

Install the current checksum-pinned release from the public tap:

```bash
brew install andrew-ships-stuff/tap/caphe
caphe version
```

The formula installs the Caphe binary from the published release artifacts. It does not install scanner executables or an inference model without a separate, explicit user action. Source-checkout users can still build the HEAD formula with `brew install --HEAD --formula ./packaging/homebrew/caphe.rb`.

## What an audit shows

Human-readable audits narrate the real workflow as it runs. Tasks may complete in a different order when scanners run concurrently:

```text
$ caphe audit .
Caphe audit
  Target    .
  Workflow  caphe:default (fixed DAG)

→ Running SAST scan with Opengrep...
→ Running SBOM inventory with Syft...
○ secret scan with Gitleaks skipped — gitleaks unavailable
  Fix: run caphe setup --install; or install only this scanner with brew install gitleaks
✓ SAST scan with Opengrep done — 12 findings · 1.4s
✓ SBOM inventory with Syft done — 0 findings · 2.1s
✓ Deterministically normalized and correlated 18 scanner findings
→ Using Qwen2.5-1.5B-Instruct-Q4_K_M.gguf to interpret 18 findings as unverified hypotheses...
✓ Model proposed 3 repository priorities (hypothesis · unverified)
✓ Built deterministic remediation plan — 9 groups from 18 findings
```

Interactive audits enable the pinned, bounded CPU model by default and report how many schema-valid hypotheses, repository priorities, and possible duplicate-group proposals they accepted. Use `--ai=false` for scanner-only execution. Non-interactive and `--json` audits remain deterministic-only unless AI is explicitly enabled or saved through `caphe setup`; `--json` always suppresses the human narrative so stdout stays machine-readable.

## Self-hosted service

`caphe cluster` exposes the same scanner-driven audit engine through an authenticated API and horizontally scalable workers. Development deployments are included for Docker Compose and Kubernetes:

```bash
docker compose -f deployments/docker/compose.yaml up --build --scale worker=3
helm upgrade --install caphe deployments/helm/caphe --set auth.existingSecret=caphe-auth
```

See [docs/cluster.md](docs/cluster.md) for authentication, storage, network isolation, submission, and current scalability boundaries. Cluster workers intentionally disable inference today; adding service-side CPU inference requires server-owned model, digest, and budget policy.

## GitHub CI for other repositories

Caphe ships a reusable composite Action and a fork-safe two-workflow review pattern. See [CI_SETUP_FOR_NEW_REPOS.md](CI_SETUP_FOR_NEW_REPOS.md) for complete copy/paste analyzer and trusted-publisher workflows, required permissions, branch-protection guidance, optional bounded CPU inference, and the pinned upgrade procedure. The consumer template currently uses `caphe:git-security` for GitHub Actions scanning; it does not claim the full local `caphe audit .` scanner suite.

## Five-minute local demo

The included fixture is deliberately vulnerable and must not be deployed.

```bash
go build -o caphe ./cmd/caphe
./caphe workflows validate caphe:demo-local
./caphe compile caphe:demo-local --output demo.lock.json
./caphe validate demo.lock.json
./caphe run demo.lock.json --target examples/vulnerable-go
./caphe findings list
./caphe report --format json --output caphe-report.json
./caphe report --format sarif --output caphe-report.sarif
./caphe report --format html --output caphe-report.html
```

`caphe:demo-local` (bundled in the binary) uses real Opengrep and Syft executables. Its Opengrep rule is stored with the target, so the demo does not fetch a ruleset. The broader default workflow additionally uses Grype and treats unavailable Gitleaks/Opengrep tasks as optional.

State defaults to the user config directory under `caphe/`. Use `--data-dir PATH` for isolated runs.

Initialize state and add only missing repository security configuration with:

```bash
caphe init --project .
```

This creates `.poutine.yml` and `.github/dependabot.yml` when absent. Existing files are reported and never overwritten. Use `--no-project-config` when only local Caphe state should be initialized.

This `init` command is optional and is not required before `audit`; `caphe setup` already initializes the local database and artifact directories. `init --project` exists specifically for adding the repository configuration files above.

## End-to-end tests

The primary integration path builds the real CLI, compiles and validates a workflow, runs a controllable scanner process, persists findings to SQLite, and validates SARIF output:

```bash
make test-e2e
```

The real-tool path scans this repository with Poutine through Caphe's compiled executor:

```bash
make install-tools
make test-e2e-real
```

## Workflow example

```yaml
apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata: {name: local-demo, version: "1.0.0"}
spec:
  target: {type: repository}
  policies:
    network: restricted
    executeGeneratedCode: false
    allowActiveTesting: false
  tasks:
    - id: sast
      uses: scanner.opengrep
      with: {ruleset: .caphe/security.yaml}
    - id: normalize
      uses: core.normalize
      needs: [sast]
```

Caphe passes scanner arguments as an argument array, never through a shell. Repository content remains untrusted; ordinary subprocess execution is not a strong sandbox. Read [docs/security.md](docs/security.md) before scanning hostile repositories.

The additional adapters can be selected in any custom workflow:

```yaml
tasks:
  - id: dependency-vulnerabilities
    uses: scanner.osv
    optional: true
    with: {offline: true}
  - id: infrastructure
    uses: scanner.checkov
    optional: true
    with: {framework: "terraform,kubernetes"}
  - id: kubernetes
    uses: scanner.kubescape
    optional: true
    with: {useArtifactsFrom: .kubescape}
  - id: policy
    uses: scanner.opa
    optional: true
    with:
      policy: policy/deny.rego
      input: policy/input.json
      query: data.caphe.deny
```

OPA queries should return a boolean, string, or collection of objects. Object results may include `id`, `message`, `severity`, `path`, and `line`. OSV-Scanner normally uses its remote vulnerability database; set `offline: true` after pre-downloading its local database. Checkov runs with result upload and policy downloads disabled, and Caphe redacts source blocks and evaluated values by default. Set `includeSensitiveOutput: true` only when full Checkov evidence is explicitly required and the artifact store is protected. Set Kubescape's `useArtifactsFrom` to a pre-downloaded artifact directory when it must remain offline.

## Terminal and automation output

Caphe commands are human-readable by default. Diagnostics, scanner coverage, workflow execution, findings, validation, and AI status use aligned sections with `✓`, `✗`, `!`, and `○` status marks. Audits narrate real scanner, remediation, and inference stages as they happen; other long-running workflow commands use a spinner only in an interactive terminal. Redirected output never receives terminal control sequences.

Pass the global `--json` flag anywhere in the command to retain stable machine-readable output:

```bash
caphe doctor                 # terminal dashboard
caphe doctor --json          # JSON for scripts and CI
caphe findings list          # readable finding list
caphe findings list --json   # structured findings
```

`caphe report` defaults to a readable table. Use `--format json`, `--format sarif`, or `--format html` for report artifacts; `caphe report --json` also selects JSON when no explicit format is supplied.

## License

MIT. See [LICENSE](LICENSE).
