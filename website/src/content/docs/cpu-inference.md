---
title: CPU inference
description: The implemented loopback llama.cpp boundary, model recommendations, structured contracts, caching, and fallbacks.
---

import { Aside } from '@astrojs/starlight/components';

Audits enable the pinned CPU model by default, including JSON and non-interactive execution, unless a saved preference disables it. Pass `--ai=false` for scanner-only execution. Release binaries embed the verified native runtime; model weights are cached separately. Caphe automatically manages a private loopback `llama.cpp` subprocess with GPU offload disabled.

## What exists today

- CPU, memory, disk, container, and basic limit inspection.
- Conservative recommendations based on current available memory and a safety reserve.
- Three GGUF Q4_K_M candidate entries, all labeled `candidate-unvalidated`.
- A loopback-only HTTP provider using `llama.cpp`'s chat completions interface.
- Strict JSON-schema output for per-finding remediation, repository synthesis, remediation-group deduplication, and invariant analysis.
- Cache keys over model digest, prompt/schema versions, canonical context, and configuration.
- Storage of valid output only as a `hypothesized` evidence node.

`caphe audit --ai-serve` downloads the explicitly identified model, verifies its SHA-256 digest, caches it, launches the runtime on an ephemeral loopback port, and stops it after the audit. `caphe setup --install` provisions the default weights ahead of time. `make build-release` embeds the platform runtime in source builds. This packaging still uses a native subprocess and private listener, not an in-process Go model engine.

Run `caphe setup` to choose the default scanners and inference preference. Defaults are 12 model calls, 4096 input tokens, 512 output tokens, and ten minutes including model preparation. Actual chat-template tokens are counted before generation. A bounded Go worker pool reviews findings concurrently; two inference slots share one loaded model. Bundle metadata reports reviewed/unreviewed findings and dedup-group coverage.

Use `--ai-threads` to control CPU threads and `--ai-parallel` for inference slots (up to 16). Default threads use physical cores bounded by Go's effective CPU allocation. Additional slots need context memory and may reduce throughput when CPU memory bandwidth is saturated. Cluster workers share one runtime across jobs and require cached, verified model weights; job submissions cannot choose inference policy.

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

Audit finding reviews request one short sentence each for explanation and remediation. A server-reported output token limit is rejected as truncation, with token usage in the error. Try `caphe audit . --max-output-tokens 512` when an audit hits the limit (maximum 1024). Caphe does not automatically increase budgets or retry calls. A rejected review keeps the deterministic recommendation, while the separate repository synthesis may still succeed.

The model must return exactly one object containing an allowlisted invariant type, property, subjects, required evidence, an allowlisted verification strategy, and literal `confidence: hypothesis`. Unknown fields, trailing JSON, invalid values, and extra prose are rejected.

Default inference degrades cleanly when preparation fails and leaves the deterministic bundle intact with an explicit AI error. Explicit `--ai` reports an error when provisioning fails. Invalid model responses are rejected and recorded without changing scanner evidence. The model never controls the executor.
