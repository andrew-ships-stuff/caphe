# Workflows and lockfiles

The supported API is `caphe.dev/v1alpha1`, kind `SecurityWorkflow`, with a repository target and a non-empty task list. Task IDs are lowercase identifiers. `uses` must resolve to a statically registered adapter. Arbitrary executable and command configuration keys, control characters, unknown adapter settings, missing dependencies, cycles, negative resources, retries over five, and timeouts over one hour are rejected.

Supported adapters are `scanner.opengrep`, `scanner.syft`, `scanner.grype`, `scanner.gitleaks`, `scanner.poutine`, `scanner.opa`, `scanner.osv`, `scanner.checkov`, `scanner.kubescape`, `core.normalize`, `core.correlate`, and `core.verify`. Scanner-specific accepted fields are intentionally narrow; inspect the examples and [adapters.md](adapters.md).

Compilation sorts tasks and dependency lists, pins adapter contract versions, records external-version detection requirements, and hashes canonical JSON with the digest field blank. Timestamps are not part of the lock. `caphe validate` recomputes the hash and rejects adapter-version drift.

The current executor does not yet resume a previous execution checkpoint. Re-running a lock creates a new execution record, while raw identical artifacts deduplicate by digest.
