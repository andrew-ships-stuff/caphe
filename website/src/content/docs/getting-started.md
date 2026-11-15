---
title: Getting started
description: Build Caphe, install the scanners your workflow needs, and run a first local scan.
---

import { Aside, Steps, Tabs, TabItem } from '@astrojs/starlight/components';

Caphe is currently a development snapshot. The reliable installation path is a source build; a stable release channel is not claimed yet.

## Requirements

- Go 1.26 or newer.
- Git and a supported terminal.
- Only the scanner executables referenced by your selected workflow. The included local demo needs [Opengrep](https://github.com/opengrep/opengrep) and [Syft](https://github.com/anchore/syft).
- No GPU, LLM API key, Docker, Kubernetes, or database server is required.

<Steps>

1. **Clone and build**

   ```bash
   git clone https://github.com/andrew-ships-stuff/caphe.git
   cd caphe
   go build -o caphe ./cmd/caphe
   ./caphe version
   ```

2. **Inspect the environment**

   ```bash
   ./caphe doctor
   ./caphe tools doctor
   ```

   Missing scanners are reported. Caphe does not substitute generated or mock findings.

3. **Validate and compile the demo workflow**

   ```bash
   ./caphe workflows validate workflows/demo-local.yaml
   ./caphe compile workflows/demo-local.yaml --output demo.lock.json
   ./caphe validate demo.lock.json
   ```

4. **Run the deliberately vulnerable fixture**

   ```bash
   ./caphe run demo.lock.json --target examples/vulnerable-go
   ```

   <Aside type="caution" title="Fixture only">The example is intentionally vulnerable. Do not deploy it.</Aside>

5. **Inspect and export results**

   ```bash
   ./caphe findings list
   ./caphe report --format json --output caphe-report.json
   ./caphe report --format sarif --output caphe-report.sarif
   ./caphe report --format html --output caphe-report.html
   ```

</Steps>

## State location

Caphe stores SQLite state and content-addressed raw artifacts under the user configuration directory in a `caphe/` folder. Use an isolated location in CI or tests:

```bash
./caphe --data-dir .caphe-ci scan . --workflow workflows/demo-local.yaml
```

## Optional CPU inference

Inference is not required for scanning. Caphe can connect to an already-running, compatible `llama.cpp` server on loopback only.

```bash
./caphe hardware inspect --json
./caphe ai recommend --json
./caphe ai doctor --json
```

Managed runtime and model downloads are not implemented. See [CPU inference](../cpu-inference/) before using `ai analyze`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `scanner executable not found` | Install the tool required by the workflow, ensure it is on `PATH`, then run `caphe tools doctor`. |
| Lock validation fails | Recompile after changing the workflow or adapter contract. Locks are tamper-evident. |
| A required task is skipped | Inspect the execution manifest for a failed dependency. Optional dependencies must be declared in both `needs` and `optionalNeeds`. |
| Inference server unavailable | Confirm `llama-server` is listening on `localhost`, `127.0.0.1`, or `::1`. Remote endpoints are rejected. |
| Scanner runs against hostile content | Use a nonprivileged container or dedicated sandbox; ordinary subprocesses are not a strong sandbox. |
