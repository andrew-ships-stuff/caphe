# Scanner adapters

An adapter owns discovery, configuration validation, argument construction, process timeout/cancellation, bounded output capture, JSON parsing, normalization, and provenance. Caphe never uses `sh -c` to launch scanners; executable and arguments are passed separately.

Implemented:

- Opengrep: `scan --json --config RULESET .`; preserves the complete result object.
- Syft: `scan . -o cyclonedx-json|syft-json`; preserves the raw SBOM artifact and package count metadata.
- Grype: scans a dependency SBOM artifact where supplied and parses vulnerability matches without discarding the original match object.
- Gitleaks: JSON report mode with `--redact`; Caphe additionally removes secret/match/entropy fields from normalized properties.
- Poutine: analyzes local CI/CD workflows in quiet SARIF mode and parses its results while retaining the original SARIF artifact. Caphe's generated `.poutine.yml` disables Poutine's version check.

External output is capped at 64 MiB per invocation and stderr at 1 MiB. The raw output artifact is preserved only after a successful parse. The end-to-end workflow installs a checksum-verified, pinned Poutine release and scans the repository through the compiled executor.

`scripts/install-tools.sh` manages Poutine and actionlint in a Caphe-owned cache directory, defaulting to `${XDG_CACHE_HOME:-$HOME/.cache}/caphe/bin`. It does not mutate system package state. actionlint is used as a repository/CI validation companion and is not yet exposed as a scanner adapter.

To add an adapter, implement `internal/adapters.Adapter`, use a fixed ID and contract version, strictly validate JSON configuration, construct typed arguments, preserve raw output, and register it in `DefaultRegistry`. Dynamic Go plugins are intentionally unsupported.
