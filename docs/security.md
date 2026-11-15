# Security model and limitations

Workflows and repositories are untrusted. The compiler allowlists adapter IDs and configuration fields, rejects command/executable overrides, bounds retries/timeouts/resources, validates dependency references, and hashes the final lock. Runtime commands use argument arrays. Scanner stdout is bounded. Normalized Gitleaks records exclude discovered secret values. Checkov raw evidence has source blocks and evaluated values removed unless the workflow explicitly sets `includeSensitiveOutput: true`.

`caphe init --project PATH` applies a deliberately small repository baseline: it creates missing Poutine and Dependabot configuration with exclusive file creation and does not replace existing policy. This convenience is not a complete repository-hardening audit.

LLM output is untrusted. The implemented invariant contract rejects unknown fields/types, non-hypothesis confidence, and verification strategies outside a fixed registry. Inference is not part of orchestration and cannot execute commands.

Important limitations:

- Scanner subprocesses currently have ordinary user privileges. Timeouts and output bounds are not a filesystem, syscall, process, memory, or network sandbox.
- The `network: restricted` policy is recorded but not OS-enforced. Do not rely on it as an egress control.
- Symlinks inside a target are handled by each scanner; Caphe currently resolves only the target root.
- SQLite and artifacts are permission-restricted but not encrypted.
- Normalized SAST properties may include source excerpts. Reports and model prompts require appropriate data handling.
- No active testing or repository build hooks are executed by the built-in workflows.
- A scanner observation confirms what that scanner reported; it does not independently prove exploitability.

Run Caphe in a nonprivileged container or dedicated sandbox when scanning hostile repositories. Do not mount a container engine socket or grant cluster-admin.
