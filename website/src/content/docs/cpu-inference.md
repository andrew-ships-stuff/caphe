---
title: CPU inference
description: The implemented loopback llama.cpp boundary, model recommendations, structured contracts, caching, and fallbacks.
---

import { Aside } from '@astrojs/starlight/components';

Caphe's deterministic engine is fully useful without a model, but interactive audits are AI-first: they attempt the pinned CPU model by default and fall back cleanly when the runtime is unavailable. Pass `--ai=false` for scanner-only execution. Inference runs through a private loopback `llama.cpp` server.

## What exists today

- CPU, memory, disk, container, and basic limit inspection.
- Conservative recommendations based on current available memory and a safety reserve.
- Three GGUF Q4_K_M candidate entries, all labeled `candidate-unvalidated`.
- A loopback-only HTTP provider using `llama.cpp`'s chat completions interface.
- Strict JSON-schema output for per-finding remediation, repository synthesis, remediation-group deduplication, and invariant analysis.
- Cache keys over model digest, prompt/schema versions, canonical context, and configuration.
- Storage of valid output only as a `hypothesized` evidence node.

`caphe audit --ai-serve` downloads the explicitly identified model, verifies its required SHA-256 digest, caches it, launches the pinned or explicitly selected runtime on an ephemeral loopback port, and stops it after the audit. `caphe setup` provisions the checksum-pinned runtime from Homebrew or a source checkout. General-purpose model install/remove commands, inference queueing, and persistent benchmark data are not implemented.

Run `caphe setup` to choose the default scanner workflow and whether bounded CPU inference is enabled. Setup offers to install the pinned `llama.cpp` runtime, and `caphe setup --install` repairs it later. Interactive audits enable it by default even before setup; non-interactive and JSON audits require an explicit or saved preference.

## Inspect and recommend

```bash
caphe hardware inspect --json
caphe ai models --json
caphe ai recommend --json
caphe ai doctor --json
```

Recommendation reserves at least 1 GiB and otherwise 25% of total memory, then selects the largest candidate fitting **currently available** memory after that reserve. This is a fit heuristic, not a performance or security-quality result.

| Candidate registry name | Parameters | Quantization | Estimated fit budget | Validation status |
| --- | ---: | --- | ---: | --- |
| `qwen2.5-coder-0.5b-instruct-q4_k_m` | 0.5B | Q4_K_M | 1.2 GB | Candidate, unvalidated |
| `qwen2.5-coder-1.5b-instruct-q4_k_m` | 1.5B | Q4_K_M | 2.4 GB | Candidate, unvalidated |
| `qwen2.5-coder-3b-instruct-q4_k_m` | 3B | Q4_K_M | 4.8 GB | Candidate, unvalidated |

<Aside type="caution">The estimates come from the source registry. They do not include a validated allowance for KV cache, context length, concurrency, measured throughput, or task accuracy.</Aside>

## Analyze one persisted finding

With a verified model file and a compatible server already listening on loopback:

```bash
caphe ai analyze \
  --finding 'sha256:…' \
  --model qwen2.5-coder-0.5b-instruct-q4_k_m \
  --model-digest 'sha256:…' \
  --endpoint http://127.0.0.1:8080
```

The command requires a finding, model identifier, and verified content digest. The endpoint must use plain HTTP on `localhost`, `127.0.0.1`, or `::1`. The default timeout is 60 seconds, input is capped at 2,048 tokens, output at 256 tokens, and the HTTP body at 2 MiB.

## Structured contract

The model must return exactly one object containing an allowlisted invariant type, property, subjects, required evidence, an allowlisted verification strategy, and literal `confidence: hypothesis`. Unknown fields, trailing JSON, invalid values, and extra prose are rejected.

Implicit interactive inference degrades cleanly when the runtime is missing and leaves the deterministic bundle intact. Explicit required inference reports an error when provisioning fails. Invalid individual model responses are rejected and recorded without changing scanner evidence. The model never controls the executor.
