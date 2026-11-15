---
title: Cluster execution
description: Run immutable Caphe audit jobs through an authenticated API and offline worker pool.
---

`caphe cluster` exposes the normal compiled workflow and digest-verified audit bundle through a control plane and scalable workers. A job accepts exactly one immutable source: an uploaded ZIP archive or an HTTPS Git repository plus a full commit SHA.

```bash
caphe cluster workflows

caphe cluster submit --archive repository.zip \
  --workflow-digest sha256:... \
  --cpu 1 --memory 1GiB --timeout 30m --wait

caphe cluster get job-...
caphe cluster download job-... --output caphe-audit.json
```

Git branches and tags are not accepted as refs. The control plane host-allowlists Git origins, verifies the resolved commit, and turns the checkout into a bounded archive. Workers therefore need no Git credentials or network access.

## Security boundary

- Bearer tokens map to tenants; status and result downloads are tenant-scoped.
- Only server-registered compiled workflow digests can run.
- Upload, expanded-size, file-count, CPU, memory, duration, concurrency, and output limits are bounded.
- Raw scanner artifacts use temporary job-local storage. Persisted finding properties are redacted before the bundle digest is recomputed.
- Clients cannot enable AI. Any future cluster inference policy remains server-owned, loopback-only, digest-verified, bounded, and labeled hypothesis.
- Remote clients require HTTPS. Plain HTTP is accepted only on loopback.

Docker Compose and Helm packaging are included under `deployments/`. The Helm worker has default-deny ingress and egress and no Kubernetes service-account token.

:::caution
The first release uses a shared-volume filesystem queue and at-least-once leases. It does not yet provide a Kubernetes custom resource, OIDC, object storage, task-level fan-out, or exactly-once execution.
:::
