# Cluster execution

`caphe cluster` runs the same compiled workflow and audit bundle as local execution behind an authenticated control plane and a horizontally scalable worker queue. It supports uploaded ZIP archives and pull-based Git acquisition at an immutable commit.

## Submission contract

```text
caphe cluster submit \
  (--git URL --ref COMMIT_SHA | --archive FILE) \
  --workflow-digest SHA256 \
  [--cpu N] [--memory SIZE] [--timeout DURATION] \
  [--network disabled|restricted] [--wait]
```

The service enforces exactly one source, full 40- or 64-character Git commit IDs, pre-registered compiled workflow digests, Git host allowlists, compressed and expanded archive limits, file-count limits, resource admission ceilings, job timeouts, worker concurrency, report-size limits, tenant-scoped artifact access, and retention. Clients cannot upload scanner commands or AI settings.

Git acquisition occurs in the control plane with a minimal environment and no credential-bearing URL. The resolved commit must exactly match the submitted SHA. The checkout is converted into a bounded ZIP snapshot before enqueueing, so workers never need Git or network access. Submodules are not fetched.

Workers use job-local temporary SQLite and raw artifact storage, persist only redacted normalized bundles and derived reports, and then delete temporary state. AI execution is disabled in the cluster worker path. Adding it later requires server-owned model, digest, loopback, and budget policy; clients will not control it.

## CLI roles

Start a development control plane on loopback and register the bundled workflow:

```bash
caphe cluster serve --insecure-no-auth --network-enforced
```

The `--network-enforced` assertion means the surrounding runtime actually applies submitted network policy. Do not use it on an unrestricted host. Production service listeners require an authentication file:

```json
{"tokens":[{"tenant":"team-a","token":"a-random-token-of-at-least-32-characters"}]}
```

```bash
caphe cluster serve \
  --listen 0.0.0.0:8787 \
  --auth-file /run/secrets/caphe-auth.json \
  --workflow caphe:default \
  --git-host github.com \
  --network-enforced

caphe cluster worker --network-enforced --concurrency 1
caphe cluster workflows --endpoint https://caphe.example.internal
```

Submit and retrieve an audit:

```bash
export CAPHE_CLUSTER_ENDPOINT=https://caphe.example.internal
export CAPHE_CLUSTER_TOKEN='...'

caphe cluster submit --archive repository.zip \
  --workflow-digest sha256:... --cpu 1 --memory 1GiB --timeout 30m --wait

caphe cluster submit --git https://github.com/acme/repository.git \
  --ref 0123456789abcdef0123456789abcdef01234567 \
  --workflow-digest sha256:...

caphe cluster get job-...
caphe cluster download job-... --output caphe-audit.json
```

The client permits plaintext HTTP only for loopback endpoints so bearer tokens are not sent over remote cleartext connections. A reverse proxy or ingress must terminate TLS for remote use.

## Docker Compose

Copy `deployments/docker/auth.example.json` to the ignored `deployments/docker/auth.json`, replace the token, then run:

```bash
docker compose -f deployments/docker/compose.yaml up --build --scale worker=3
```

The API binds only to host loopback. Workers use `network_mode: none`, a read-only root filesystem, dropped capabilities, a temporary workspace, and a shared named volume. The cluster image installs checksum-pinned Poutine, Syft, Grype, and Gitleaks; scanners absent from the image degrade to skipped tasks.

## Helm

The chart requires an existing Secret and a storage class that supports `ReadWriteMany` when using more than one pod:

```bash
kubectl create secret generic caphe-auth \
  --from-file=auth.json=./deployments/docker/auth.json

helm upgrade --install caphe deployments/helm/caphe \
  --set auth.existingSecret=caphe-auth \
  --set image.repository=registry.example/caphe-cluster \
  --set image.tag=0.1.0-dev
```

The worker Deployment has a default-deny ingress and egress `NetworkPolicy`, no service-account token, a read-only root filesystem, and pod resource limits. The API Deployment alone performs allowlisted Git acquisition. Scale `worker.replicas`; renewable lease tokens provide at-least-once execution and stop a stale worker from publishing after its job is reclaimed.

## Current distributed boundary

This first implementation uses an atomic filesystem queue on a shared volume. It does not claim exactly-once execution, scanner-task fan-out, capability-aware placement, OIDC, encrypted storage, a `SecurityAudit` CRD, or object-store result persistence. CPU and memory requests are admitted against server policy and bounded by worker container resources; they are not dynamically assigned per job. A Kubernetes CRD/controller should be the next invocation layer after the job API and bundle schema stabilize.
