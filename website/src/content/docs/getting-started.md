---
title: Getting started
description: Build Caphe, install the scanners your workflow needs, and run a first local scan.
---

import { Aside, Steps } from '@astrojs/starlight/components';

Caphe publishes checksum-pinned release binaries through its Homebrew tap. A source build remains available for contributors.

## Requirements

- Homebrew for the shortest install, or Go 1.27+ for a source build.
- Only the scanner executables referenced by your selected workflow. The included local demo needs [Opengrep](https://github.com/opengrep/opengrep) and [Syft](https://github.com/anchore/syft).
- No GPU, LLM API key, Docker, Kubernetes, or database server is required.

<Steps>

1. **Install Caphe**

   ```bash
   brew install andrew-ships-stuff/tap/caphe
   caphe version
   ```

   For a source build, clone the repository and run `go build -o caphe ./cmd/caphe` with Go 1.27 or newer.

   On macOS or Linux, `make install` builds and installs Caphe and calls `install-tools` for the checksum-pinned managed set: Poutine, actionlint, Syft, Grype, Gitleaks, and `llama.cpp`. Opengrep requires a separate installation. The default destination is `${XDG_CACHE_HOME:-$HOME/.cache}/caphe/bin`; add it to `PATH` to invoke Caphe. Override `CAPHE_CACHE` for another cache location or `TOOLS=syft,grype` for a subset. Use `make build` to build without downloading tools.

2. **Complete first-run setup**

   ```bash
   caphe setup
   ```

   Setup initializes local state, lets you choose the default scanners and bounded CPU inference, and offers to install every missing checksum-pinned tool needed by that selection. Caphe discovers its managed tool directory automatically, so no shell `PATH` edit is required. Run `caphe setup --install` later to repair a partial installation, or `caphe doctor` to inspect it. Caphe does not substitute generated or mock findings.

3. **Run the fixed audit workflow**

   ```bash
   caphe audit .
   ```

   The terminal narrates each scanner and core task, reports skips and finding counts, then builds the deterministic remediation plan. Missing optional scanners do not fail the audit. Use `--json` for quiet, stable machine output.

4. **Optionally run the deliberately vulnerable fixture from a source checkout**

   ```bash
   ./caphe workflows validate caphe:demo-local
   ./caphe audit examples/vulnerable-go --workflow caphe:demo-local
   ```

   <Aside type="caution" title="Fixture only">The example is intentionally vulnerable. Do not deploy it.</Aside>

5. **Inspect and export results**

   ```bash
   caphe findings list
   open caphe-audit.html
   ```

</Steps>

## State location

Caphe stores SQLite state and content-addressed raw artifacts under the user configuration directory in a `caphe/` folder. Use an isolated location in CI or tests:

```bash
caphe --data-dir .caphe-ci audit . --json
```

## Optional CPU inference

Inference is not required for scanning. Audits enable it by default, including JSON and non-interactive execution; use `caphe audit . --ai=false` for scanner-only execution. Release binaries embed the native CPU runtime. Setup with installation provisions verified model weights; Caphe manages the private runtime process automatically.

```bash
caphe hardware inspect --json
caphe ai recommend --json
caphe ai doctor --json
```

Use the complete command printed by `caphe doctor` to enable `audit --ai --ai-serve`; it includes the model name, HTTPS source, and required digest. All accepted model text remains an unverified hypothesis. See [CPU inference](../cpu-inference/) for the trust boundary.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `scanner executable not found` | Run `caphe setup --install`, then `caphe tools doctor`. |
| Grype database is stale or fails to load | Run the managed `grype db update`. For persistent corruption, run `grype db delete` then `grype db update` (requires network). Repeated hydration/migration errors may need an upstream fix and a reviewed pin update; reinstalling Caphe does not repair the database. |
| Lock validation fails | Recompile after changing the workflow or adapter contract. Locks are tamper-evident. |
| A required task is skipped | Inspect the execution manifest for a failed dependency. Optional dependencies must be declared in both `needs` and `optionalNeeds`. |
| Inference server unavailable | Confirm `llama-server` is listening on `localhost`, `127.0.0.1`, or `::1`. Remote endpoints are rejected. |
| Scanner runs against hostile content | Use a nonprivileged container or dedicated sandbox; ordinary subprocesses are not a strong sandbox. |
