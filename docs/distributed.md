# Distributed execution

Distributed workers are not implemented in this local MVP. The intended design reuses the same compiled lock and executor, schedules only onto workers reporting actual tool/model/CPU/memory/trust capabilities, and uses leases plus idempotency for at-least-once execution. Exactly-once execution will not be claimed.

No Kubernetes manifests or Helm chart are shipped yet because there is no worker/control-plane binary to deploy safely.
