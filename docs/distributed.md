# Distributed execution

Distributed whole-audit workers are implemented by `caphe cluster`. The control plane registers compiled workflow locks, authenticates and tenant-scopes submissions, normalizes Git commits or uploaded archives into immutable snapshots, and enqueues jobs on shared storage. Workers claim renewable leases, execute the existing audit engine in temporary job-local state, and publish digest-verified JSON, SARIF, Markdown, and HTML reports.

Docker Compose and Helm packaging live under `deployments/`. Kubernetes workers run behind a default-deny network policy. See [cluster.md](cluster.md) for commands, security controls, and the deliberately explicit limitations of the filesystem-backed first version.

Task-level fan-out, capability-aware placement, object storage, OIDC, and a Kubernetes `SecurityAudit` custom resource remain future work. Exactly-once execution is not claimed.
