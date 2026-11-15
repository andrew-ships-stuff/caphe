# Cluster execution design

`caphe cluster` should extend the audit artifact and executor, not create a second scanning engine. Local CLI, Docker Compose, and Kubernetes workers should all consume the same immutable job specification and emit the same digest-verified audit bundle.

## Proposed user surface

```text
caphe audit [DIRECTORY|ARCHIVE]           local execution; current directory by default
caphe cluster submit --git URL --ref SHA  pull-based cluster job
caphe cluster submit --archive FILE       upload-based cluster job
caphe cluster get JOB                     job status and scanner coverage
caphe cluster download JOB                fetch the audit bundle and derived reports
```

Git jobs must resolve a branch or tag to a commit and record the commit SHA before execution. Production policy may require a SHA outright. Archive jobs use the same safe preparation boundary as local ZIP audits and add server-side compressed-size, expanded-size, file-count, and request-size quotas.

## Kubernetes-native API

The natural invocation is a namespaced `SecurityAudit` custom resource reconciled by a Caphe controller. Its spec contains exactly one source (`git` or `archiveRef`), a workflow digest, resource limits, and an optional schedule reference. Status contains phase, conditions, task coverage, result digest, and an artifact reference. The controller creates one Kubernetes Job per audit; each Job may run scanner tasks in one worker initially and can later fan out immutable task leases to several workers.

The controller must not accept arbitrary scanner commands. It resolves only compiled workflows and registered typed adapters. Workers receive an immutable job document, prepare the source in an ephemeral volume, run the existing deterministic executor, and publish a bundle atomically. LLM annotation remains optional, loopback-only within the worker pod, budgeted, digest-verified, and unable to affect job policy.

```text
SecurityAudit CR/API
        |
   controller
        |
 Kubernetes Job / Compose queue
        |
  isolated worker(s) ---> result store ---> JSON bundle / HTML / SARIF
```

Kubernetes itself should own scheduling, retries, leases, CPU/memory limits, and horizontal scaling. A `NetworkPolicy` denies worker egress by default. Git acquisition is a distinct init step with narrowly enabled egress; uploaded archives need none. Scanner and rule assets ship in digest-pinned OCI images so an installed cluster can run without internet access.

## Storage and portability

SQLite remains appropriate for a local audit and a single worker workspace, but it is not the shared coordination database for multiple pods. Each worker should use job-local SQLite and upload the finalized bundle and raw content-addressed artifacts to a pluggable result store. The first Kubernetes implementation can use a PVC; an S3-compatible store can be optional. CR status stores only bounded metadata, never the full report.

Docker Compose should run the same API/controller and worker image with a bind-mounted or named-volume result store. A single-process profile stays simple for laptops; a multi-worker profile adds an explicit lease-capable queue rather than sharing a SQLite file across containers.

## Delivery order

1. Freeze and validate the job/source/result schemas; keep the audit bundle backward compatible.
2. Add pinned Git acquisition and reuse ZIP preparation, with quotas and provenance in the bundle.
3. Extract a worker entry point around the existing audit package and add cancellation/idempotency tests.
4. Add the HTTP submission API and Docker Compose profile.
5. Add the `SecurityAudit` CRD, controller, Helm chart, RBAC, pod security settings, and default-deny networking.
6. Add task fan-out only after whole-audit Jobs are reliable; parallel workers must never select findings by “latest execution.”
