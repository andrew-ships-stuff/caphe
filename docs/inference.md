# CPU-only inference

Audit finding reviews request compact, one-sentence explanation and remediation fields. If the server reports that generation reached its token limit, Caphe rejects the completion and reports truncation with token usage, rather than a generic JSON error. For an audit that hits this limit, try `caphe audit . --max-output-tokens 512` (maximum 1024). Budgets are not increased automatically and calls are not retried. Invalid reviews retain the deterministic recommendation; a separate repository synthesis can still succeed. All accepted model output remains an unverified hypothesis.

Inference is enabled by default for interactive, non-interactive, and JSON audits, unless disabled by saved setup preferences or `--ai=false`. Release binaries embed the pinned native runtime; model weights remain a separately cached, digest-verified asset. `caphe setup --install` provisions those weights. Source development builds can use managed tools or `make build-release` to embed the runtime.

The runtime explicitly disables GPU layers. Threads default to physical cores bounded by Go's effective `GOMAXPROCS`; `--ai-threads` overrides this. Two inference slots share one loaded model by default, using continuous batching. `--ai-parallel` accepts up to 16 slots. CPU memory bandwidth often limits generation before RAM capacity; benchmark your actual model before increasing concurrency. Each slot gets its own input-plus-output context allowance. Model size is never silently increased based on RAM.

Use `--ai-offline --ai-model-cache PATH` for an audit that must use existing weights without downloading them. When scanners produce no findings, inference reports `no_evidence` and does not load a model. This does not imply complete scanner coverage. AI metadata includes status, prompt/completion token totals, and elapsed time for tuning and diagnostics.

Audit reviews use a bounded Go worker pool, deterministic job ordering, and round-robin selection across remediation groups. Defaults are 12 generation attempts, 4096 input tokens, 512 output tokens, and ten minutes including model preparation. The provider applies the actual chat template and tokenizes it before generation; oversized input is rejected. Bundle AI metadata reports reviewed and unreviewed findings and the number of groups covered by bounded dedup batches. Cross-batch AI comparisons are not exhaustive. Scanner evidence and deterministic grouping remain authoritative.

```bash
caphe hardware inspect --json
caphe ai recommend --json
caphe ai status --json
caphe ai doctor --json
```

Recommendations reserve at least 1 GiB and otherwise 25% of installed memory, then use currently available memory rather than total RAM. Registry entries are marked `candidate-unvalidated`; they are not claims of security-task accuracy. KV cache, context size, concurrency, measured throughput, and observed accuracy must be incorporated before automated provisioning is safe.

With an already running compatible server and a verified model digest, `caphe ai analyze --finding ID --model NAME --model-digest sha256:...` submits a bounded request. Valid output is cached using the model digest, prompt/schema versions, canonical context hash, and configuration hash, then stored only as a `hypothesized` graph node.

The HTTP provider accepts only loopback endpoints, rejects redirects, applies a client timeout, wraps repository content as untrusted data, requests strict JSON-schema output, limits response bytes, and rejects invalid JSON. Caphe manages the native `llama-server` process automatically and stops it after an audit. This is an embedded runtime distribution, not an in-process Go inference implementation: a private loopback listener still exists. Cluster workers keep a single model process alive across jobs and require pre-provisioned verified weights; submissions cannot select model URLs, executables, or policy. General-purpose model removal and benchmark persistence are not implemented.
