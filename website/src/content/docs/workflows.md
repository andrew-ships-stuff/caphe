---
title: Workflows and lockfiles
description: The verified Caphe v1alpha1 workflow schema, compilation rules, dependencies, and reproducibility boundary.
---

Caphe accepts declarative YAML at API version `caphe.dev/v1alpha1` and kind `SecurityWorkflow`. The current target type is `repository`.

```yaml
apiVersion: caphe.dev/v1alpha1
kind: SecurityWorkflow
metadata:
  name: local-demo
  version: "1.0.0"
spec:
  target:
    type: repository
  policies:
    network: restricted
    executeGeneratedCode: false
    allowActiveTesting: false
  defaults:
    timeoutSeconds: 300
    retries: 0
  tasks:
    - id: sast
      uses: scanner.opengrep
      with:
        ruleset: .caphe/security.yaml
    - id: normalize
      uses: core.normalize
      needs: [sast]
```

## Task fields

| Field | Meaning |
| --- | --- |
| `id` | Lowercase task identifier, unique within the workflow. |
| `uses` | A statically registered adapter ID. Arbitrary commands are unsupported. |
| `needs` | Dependencies that must finish before this task can run. |
| `optionalNeeds` | Dependencies allowed to fail; each must also appear in `needs`. |
| `optional` | Whether failure of this task may be tolerated by downstream policy. |
| `with` | Adapter-specific, strictly validated configuration. |
| `runtime` | Per-task timeout, retries, and backoff. |
| `resources` | Declarative CPU millis and memory bytes. Scheduling enforcement is limited locally. |

Compilation rejects unknown adapter settings, executable or command overrides, control characters, missing dependencies, cycles, negative resources, more than five retries, and timeouts over one hour.

## Compilation and validation

```bash
caphe workflows validate workflows/default.yaml
caphe compile workflows/default.yaml --output workflow.lock.json
caphe validate workflow.lock.json
```

Compilation normalizes ordering, pins adapter contract versions, records external-version detection requirements, and hashes the result. `caphe validate` recomputes the digest and rejects tampering or adapter-version drift.

## Error handling

The runtime supports dependency-aware partial failure, cancellation, task timeouts, bounded retry, and optional dependencies. It retains raw output only after a successful parse, then records an execution manifest whether the overall run succeeds or partially fails.

## Reproducibility boundary

Caphe guarantees canonical control-plane plans for identical normalized compilation inputs. It does not claim identical scanner results if binaries, rule sets, vulnerability databases, repositories, or the environment change. Preserve the lock, execution manifest, raw artifacts, scanner versions, and target revision together.
