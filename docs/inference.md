# CPU-only inference

Inference is optional but AI-first in the interactive audit experience. An interactive `caphe audit` uses the pinned CPU model by default when the runtime is available; `--ai=false` selects scanner-only execution. Non-interactive and JSON audits do not enable inference implicitly unless that preference was saved by `caphe setup`. Setup offers to install the checksum-pinned `llama.cpp` runtime and Caphe automatically discovers its managed tool directory. Caphe exposes hardware inspection, conservative model recommendations, a loopback-only `llama.cpp` HTTP provider, and strict schema validation.

```bash
caphe hardware inspect --json
caphe ai recommend --json
caphe ai status --json
caphe ai doctor --json
```

Recommendations reserve at least 1 GiB and otherwise 25% of installed memory, then use currently available memory rather than total RAM. Registry entries are marked `candidate-unvalidated`; they are not claims of security-task accuracy. KV cache, context size, concurrency, measured throughput, and observed accuracy must be incorporated before automated provisioning is safe.

With an already running compatible server and a verified model digest, `caphe ai analyze --finding ID --model NAME --model-digest sha256:...` submits a bounded request. Valid output is cached using the model digest, prompt/schema versions, canonical context hash, and configuration hash, then stored only as a `hypothesized` graph node.

The HTTP provider accepts only `http://localhost`, `127.0.0.1`, or `::1`, applies a client timeout, wraps repository content as untrusted data, requests strict JSON-schema output, limits response bytes, and rejects invalid JSON. `caphe audit --ai --ai-serve` can download a model from an explicit HTTPS URL, verify its required SHA-256 digest, cache it, launch a pinned or explicitly selected `llama-server` on an ephemeral loopback port, and stop that subprocess after the audit. The repository installer can provision the pinned runtime from a source checkout. General-purpose `ai setup`, model install/remove commands, inference queueing, and benchmark persistence are not implemented.
