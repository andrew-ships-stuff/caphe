# CPU-only inference

Inference is optional. Caphe currently exposes hardware inspection, conservative model recommendations, a provider interface, a loopback-only `llama.cpp` HTTP provider, and strict validation for `infer_security_invariant` output.

```bash
caphe hardware inspect --json
caphe ai recommend --json
caphe ai status --json
caphe ai doctor --json
```

Recommendations reserve at least 1 GiB and otherwise 25% of installed memory, then use currently available memory rather than total RAM. Registry entries are marked `candidate-unvalidated`; they are not claims of security-task accuracy. KV cache, context size, concurrency, measured throughput, and observed accuracy must be incorporated before automated provisioning is safe.

With an already running compatible server and a verified model digest, `caphe ai analyze --finding ID --model NAME --model-digest sha256:...` submits a bounded request. Valid output is cached using the model digest, prompt/schema versions, canonical context hash, and configuration hash, then stored only as a `hypothesized` graph node.

The HTTP provider accepts only `http://localhost`, `127.0.0.1`, or `::1`, applies a client timeout, wraps repository content as untrusted data, requests strict JSON-schema output, limits response bytes, and rejects invalid JSON. Managed runtime/model installation, checksum registry, process lifecycle, cache commands, inference queueing, and benchmark persistence are not implemented yet. Caphe therefore does not advertise `ai setup` or model install/remove commands.
