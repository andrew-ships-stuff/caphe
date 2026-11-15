# Roadmap

Implemented in this snapshot: foundational Go CLI; SQLite schema and content-addressed artifacts; canonical workflow compilation and tamper validation; bounded concurrent local execution; Opengrep/Syft/Grype/Gitleaks/Poutine/OPA/OSV-Scanner/Checkov/Kubescape adapters; JSON/SARIF/HTML reports; typed evidence allowlists and exact source-location graph edges; CPU hardware inspection and recommendations; loopback `llama.cpp` provider contract; strict invariant validation; CLI end-to-end coverage; checksum-pinned repository tool provisioning; and real Opengrep/Syft and Poutine execution paths.

Next: checkpoint/resume and idempotency keys; typed task I/O schemas and `${tasks.*}` reference checking; richer SBOM/package/image/RBAC graph correlation; verification strategies and state transitions; inference response cache commands; managed checksum-pinned llama.cpp/model provisioning; positive/negative authorization demo; benchmark harness; remaining OS sandbox controls; import/export; pinned real-scanner CI for the newer adapters; and Windows CI.

Later: worker/scheduler leases, NATS transport if operational testing justifies it, Kubernetes/Helm packaging, and security-knowledge compilation after validation/approval controls exist.
