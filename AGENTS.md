# AGENTS.md

Instructions for AI coding agents working in this repository. Read this before changing anything. The human-facing intro is in [README.md](README.md); security posture is in [docs/security.md](docs/security.md).

## Project overview

Caphe is a local-first, CPU-native security workflow compiler and executor in Go (single module, CLI entry `cmd/caphe`, everything else under `internal/`). It compiles declarative YAML workflows to content-addressed lock artifacts, executes a fixed DAG of installed scanners (Opengrep, Syft, Grype, Gitleaks, Poutine) through typed adapters, normalizes/correlates findings into SQLite, and emits JSON/SARIF/HTML reports. The hero command is:

```bash
caphe audit [dir]   # aggregate -> correlate -> optional CPU LLM -> one digest-pinned bundle (JSON+SARIF+MD)
```

Core invariants agents must preserve:
- Deterministic engine: no LLM required, no shell interpolation for scanner args, no network unless a task needs it.
- LLM is optional, loopback-only (`127.0.0.1`), budgeted (calls/tokens/time), model digest-verified, and its output is **always** labeled `hypothesis` — never promoted to a confirmed finding and never allowed to determine policy.
- Missing optional scanners degrade to `skipped` tasks, never fabricated findings and never failed runs.

## GitHub project governance

- `main` is protected and accepts changes through pull requests only. Never push directly, force-push, delete the branch, or bypass required checks; use a short-lived branch and let GitHub enforce the merge gate.
- Attribute every change to a tracked GitHub work item: link the pull request to its issue or originating [Discussion](https://github.com/andrew-ships-stuff/caphe/discussions), and assign it to the active [milestone](https://github.com/andrew-ships-stuff/caphe/milestones). Use closing keywords for issues when the PR fully resolves them.
- Use Discussions for proposals, questions, and decisions that should be settled before implementation. Summarize the decision in the linked PR so the code history retains the rationale.
- Keep durable contributor and operational guidance in the [wiki](https://github.com/andrew-ships-stuff/caphe/wiki). Update the relevant wiki page in the same work item when a change invalidates it; repository-local technical truth still belongs in versioned docs and code.
- Before handing off a change, report the linked issue or Discussion, milestone, branch, and pull request. If any attribution is unavailable, call it out explicitly instead of silently leaving the change untracked.

## Concurrent agent rules (read first)

Multiple agents and humans write to this working tree **at the same time**. Assume the index and neighboring files are contaminated until proven otherwise.

1. **Never `git add -A`, `git add .`, or `git commit -a`.** Stage only the explicit paths you edited and commit with an explicit pathspec: `git commit -m "..." -- path1 path2/...`.
2. Before every commit, run `git status --short` and `git diff --cached --stat` and verify **only your files** are included. Unrelated staged changes (README rewrites, website/logo work, etc.) belong to other agents — never commit, reset, stash, or overwrite them.
3. If a file you need to touch already has someone else's uncommitted changes, do not clobber it: coordinate around the conflict or leave it and note the collision in your final message.
4. **Never commit secrets**: no `.env` files, tokens, private keys, `~/.caphe` state, or scanner output that embeds credentials. Before committing anything new, scan the staged diff:
   ```bash
   git diff --cached | grep -Ei 'ghp_|github_pat_|AKIA[0-9A-Z]{16}|BEGIN.*PRIVATE|password\s*[:=]|hf_[A-Za-z0-9]{30,}'
   ```
   Any hit must be resolved before committing. Gitleaks secret properties are redacted in `internal/adapters/scanner.go` — keep it that way. `GITHUB_TOKEN` is stripped from all spawned subprocesses (`internal/inference/serve.go` allowlist); do not widen that allowlist casually.
5. Keep commits small and auditable: one logical change per commit, and every commit must pass `gofmt -l .`, `go vet ./...`, and `go test ./...` on its own.

## Setup, build, and test commands

Requires Go 1.26+ (see `.github/workflows/ci.yml`, which tests ubuntu/macos/windows).

```bash
make build                 # go build -o bin/caphe ./cmd/caphe
go test ./...              # unit + integration suites
make test-e2e              # tests/e2e: builds the real CLI, drives it with fake scanner scripts
make test                  # go test ./...
make vet                   # go vet ./...
make check                 # test + vet + build
```

Always run before committing (CI and the Caphe PR-analysis gate will fail otherwise):

```bash
gofmt -l .                 # must print nothing
go vet ./...
go test ./...
```

Validate any change to `.github/workflows/*.yml` or `action.yml` with actionlint:

```bash
bash scripts/install-tools.sh --tools actionlint
"${XDG_CACHE_HOME:-$HOME/.cache}/caphe/bin/actionlint" .github/workflows/*.yml action.yml
```

Real-tool e2e (requires managed tools installed first):

```bash
make tools-install         # pinned poutine + actionlint; add: --tools syft,grype,gitleaks,llama.cpp
make test-e2e-real
```

## Testing instructions

- Tests are table-driven and use fake executables on `PATH` (POSIX `#!/bin/sh` scripts emitting canned JSON). See `TestAuditHeroCommandAggregatesAndDegrades` in `tests/e2e/cli_test.go` for the canonical pattern.
- A fake `llama-server` is implemented by re-execing the test binary with `CAPHE_FAKE_LLAMA=1` (`internal/inference/serve_test.go` `TestMain`). Reuse it for anything touching inference; do not hit real endpoints in default tests.
- Real CPU-inference test is opt-in (downloads ~1GB): `CAPHE_TEST_LLAMA=1 go test ./internal/inference -run TestRealLlamaCPPDogfood -v`.
- Windows CI is real: POSIX-only fixtures must `t.Skip()` on `runtime.GOOS == "windows"`, and don't rely on Go file mode bits there.
- Add or update tests for the code you change even if nobody asked. LLM-boundary code (schemas in `internal/inference/*.go`) must have validator tests: reject unknown fields, trailing JSON, fabricated evidence IDs, and out-of-bounds text.

## Code style

- Standard `gofmt`; gofmt-clean is non-negotiable. Dense, compact Go matching existing files; use `any` over `interface{}`.
- Comments only where the code is genuinely non-obvious (e.g., trust-boundary rationale); no narrating comments.
- Cobra commands are `func (a *app) xCmd() *cobra.Command` methods in `internal/cli/`; shared state lives on `app` (`a.dataDir`, `a.registry`, `a.print`).
- Adapters live in `internal/adapters`: one `ID()` + `Detect` + `Validate` + `Execute` per tool, with strict config allowlists and a `ParseScannerOutput` case. Add new adapters there, never ad hoc.
- All LLM prompts ship as `const` SystemPrompt + JSONSchema pairs with a `Validate*` function that uses `DisallowUnknownFields`, rejects trailing content, bounds all strings/arrays, and requires `confidence == "hypothesis"` with cited evidence IDs drawn from an allowlist. Follow `internal/inference/synthesis.go`.
- Workflow references resolve as a file path or `caphe:<name>` against the embedded FS in `internal/workflow/bundled/`. There is no top-level `workflows/` directory; don't reintroduce references to it (README cleanup for this is owned by another agent's staged change).

## Pinned versions — do not blindly take "latest"

Every external binary/model is pinned with an explicit version **and** sha256. Never auto-bump to whatever `latest` is, and never install a tool from an unpinned URL. Pins:

| Asset | Version | Pin location |
|---|---|---|
| poutine | 1.1.4 | `scripts/install-tools.sh` (upstream checksums) |
| actionlint | 1.7.8 | `scripts/install-tools.sh` (upstream checksums) |
| syft | 1.57.1 | `scripts/install-tools.sh` (hardcoded per-platform sha256) |
| grype | 0.121.3 | `scripts/install-tools.sh` (hardcoded per-platform sha256) |
| gitleaks | 8.30.1 | `scripts/install-tools.sh` (hardcoded per-platform sha256) |
| llama.cpp (`llama-server`) | b12359 | `scripts/install-tools.sh` **must match** `managedLlamaPinnedVersion` in `internal/inference/serve.go` |
| AI dogfood model | Qwen2.5-1.5B-Instruct Q4_K_M | `.github/workflows/caphe-pr.yml` `ai-model-url` + `ai-model-digest` |
| GitHub Actions | pinned by commit SHA | `.github/workflows/*.yml` (Dependabot bumps these) |
| Go deps | — | `go.mod`/`go.sum` (Dependabot) |

Refresh procedure (run periodically, e.g. quarterly, as its own commit titled "Bump managed tools ..."): check releases deliberately (`gh api repos/<owner>/<repo>/releases/latest`), verify each asset's `sha256` from the API `digest` field — for HuggingFace GGUF use the `lfs.oid` from `https://huggingface.co/api/models/<repo>/tree/main` — then update **all** pin sites together, run `make tools-install`, the full suite, and `make test-e2e-real`. For llama.cpp also re-verify the tarball layout (flat `llama-server` + co-located libs) and rerun `CAPHE_TEST_LLAMA=1 go test ./internal/inference -run TestRealLlamaCPPDogfood`. Never update a pin without its checksum; never use `latest`/floating tags.

## Architecture map

- `cmd/caphe` → `internal/cli` (cobra). Hero: `audit`. Plumbing: `compile`, `validate`, `run`, `scan`, `report`, `findings`, `graph`, `github` (`analyze`/`validate`/`publish`/`annotations`), `ai`, `doctor`, `tools`, `workflows`.
- `internal/workflow` (parse + bundled FS) → `internal/compiler` (lock plan, digest, gates) → `internal/runtime` (DAG executor with retries, budgets, artifacts) → `internal/adapters` (typed scanners) → `internal/storage` (SQLite evidence) → `internal/reporting` (JSON/SARIF/HTML).
- `internal/audit` composes the above into the bundle; `internal/githubreview` implements the untrusted-analysis → trusted-publish split; `internal/inference` holds the llama.cpp provider, subprocess launcher (ephemeral loopback port, so users' own llama.cpp on :8080 never conflicts), model cache, and all prompt/schema/validator sets.
- Dogfooding CI: `caphe-pr.yml` (untrusted `caphe github analyze` with `ai-serve: true`, `contents: read` only) → `caphe-publish.yml` (trusted `workflow_run` publisher, only exists/runs on `main`; re-validates artifact identity before posting).

## Keep docs and the GitHub Pages site in sync with core changes

The site at `website/` (deployed by `.github/workflows/pages.yml` on merge to `main`) and the docs are part of the feature: **any change to user-visible core behavior updates them in the same PR**, not "later".

- Triggers — if your diff touches any of these, you owe a docs/site update (or an explicit note why you don't):
  - CLI commands, flags, defaults, or the hero flow: `internal/cli/`
  - Scanner adapters, supported tools, and managed installs: `internal/adapters/`, `scripts/install-tools.sh`
  - Bundled workflows: `internal/workflow/bundled/` (site demo references `caphe:default`/`caphe:demo-local` by name)
  - Report/bundle output formats and artifact names: `internal/audit/`, `internal/reporting/`, `internal/githubreview/`
  - AI/LLM surfaces, prompts, budgets, pinned dogfood model: `internal/inference/`, `caphe-pr.yml`
- Where to update:
  - Commands shown to users: `website/src/components/TerminalDemo.astro` — every command it displays must be a valid invocation at this revision (the tabs are the #1 drift source)
  - Feature/architecture claims and scanner lists: `website/src/pages/index.astro`, `website/src/components/ArchitectureDiagram.astro`
  - Roadmap and benchmark claims: `website/src/pages/roadmap.astro`, `website/src/pages/benchmarks.astro`; shipped-vs-planned boundary: `docs/roadmap.md`
  - Human onboarding: `README.md` and `Makefile` targets (e.g., `make demo` must keep working)
- Honesty rules (mirrors [website/AGENTS.md](website/AGENTS.md)): never advertise unimplemented behavior; AI output stays labeled hypothesis/unverified; versions/model/scanner names match `internal/cli/root.go` (`Version`) and the pin table above.
- Verify before committing: from `website/`, `npm ci && npm run build` (runs `astro check`) and `npm run test:links`; for Go-side docs, `make demo` style commands in README/Makefile must actually run.
- If a docs/site file is dirty with another agent's uncommitted edits, do not clobber it: land the code change, then report the exact stale file and required edit in your final message so the drift is tracked instead of silently shipped.

## Commit and PR conventions

- Subject: imperative, ≤ 72 chars, starts with Add/Fix/Bump/Refactor (e.g., "Fix empty findings report breaking GitHub PR analysis"); body as short `- ` bullets.
- PR titles are descriptive sentences, not one-word summaries; describe behavior, not file names.
- CI gates that must be green before merge: `CI` (three-OS matrix), `End-to-end`, `real-poutine`, and `Caphe PR analysis` (a new high/critical finding fails the PR).
- `go.work`, `bin/`, `dist/`, `caphe-audit.*`, and `caphe-pr-review.json` are outputs, not inputs — don't commit them.
