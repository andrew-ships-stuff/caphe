---
title: Architecture
description: How Caphe compiles workflows, executes a fixed DAG, preserves evidence, and bounds optional inference.
---

import { Aside } from '@astrojs/starlight/components';

Caphe separates workflow compilation from execution. The lock artifact is typed data, not generated executable code.

```text
workflow YAML
    │
    ▼
security + syntax gates ──► canonical lock + SHA-256 digest
                                      │
target ──► fixed DAG scheduler ──► typed adapters ──► raw artifacts
                                      │                    │
                                      ▼                    ▼
                                  findings ──► SQLite evidence ──► reports
                                                    │
                                                    └──► optional bounded hypothesis
```

## Workflow compiler

The compiler parses `caphe.dev/v1alpha1` YAML into Go types, validates task IDs and dependencies, rejects cycles, checks policy bounds, resolves every `uses` value against the static adapter registry, sorts tasks and dependency lists, and records adapter contract versions. It hashes canonical JSON with the digest field blank. Timestamps do not enter the hash.

The lock records four gates separately: Security, Syntax, Execution, and Accuracy. In the current snapshot, a lock can be emitted after Security and Syntax pass; Execution and Accuracy remain `not_evaluated` unless workflow-specific fixtures support them.

## Deterministic executor

The executor chooses runnable tasks only from declared dependencies. Ready tasks are sorted by task ID before dispatch. Concurrency may change wall-clock completion order, never dependency order or the normalized plan.

- A required dependency failure deterministically skips its consumers.
- A dependency in `optionalNeeds` may fail without blocking its consumer.
- Retries, timeouts, and resource declarations are bounded during compilation.
- Re-running creates a new execution record; checkpoint/resume is not implemented.

## Adapter boundary

Adapters own discovery, strict configuration validation, argument construction, timeout and cancellation, bounded output capture, JSON parsing, normalization, and provenance. Commands are passed as executable plus argument array—never through `sh -c`.

Implemented external adapters are Opengrep, Syft, Grype, Gitleaks, Poutine, OPA, OSV-Scanner, Checkov, and Kubescape. Core adapters normalize, correlate the currently supported exact source relationships, and provide a verification foundation.

## Evidence and storage

Successful raw scanner output is written under SHA-256 content paths. SQLite stores executions, task results, findings, graph nodes, and graph edges. Finding-to-file relationships use exact scanner locations; similarity is not treated as proof.

The current database materializes scanner observations and exact source references. Rich package, image, workload, and RBAC correlation remains planned.

## CPU inference boundary

The optional provider speaks to a loopback-only `llama.cpp` HTTP endpoint. Inputs wrap repository fields as untrusted data. Output must match a strict JSON schema, fit response limits, and declare `confidence: hypothesis`. It cannot add tasks, choose the next task, construct command lines, or confirm itself.

<Aside type="note">The current provider supports bounded semantic inference after a finding exists. AI-assisted workflow generation is architectural direction, not a shipped command.</Aside>

## Trust boundaries

| Boundary | Current control | Important limitation |
| --- | --- | --- |
| Workflow input | Static adapters, allowlisted fields, bounded policy, lock digest | A valid workflow may still invoke an installed scanner. |
| Repository | Treated as untrusted data; no generated code execution | Scanner subprocesses have the invoking user's ordinary privileges. |
| Scanner process | Argument arrays, timeouts, 64 MiB stdout and 1 MiB stderr caps | No syscall, filesystem, memory, or enforced network sandbox yet. |
| Inference server | Loopback HTTP only, timeout, schema and byte limits | Model behavior is probabilistic and model accuracy is unvalidated. |
| Local storage | Permission-restricted files and SQLite | Data is not encrypted at rest. |

## Local and distributed execution

Local execution and whole-audit distributed workers are implemented. `caphe cluster` registers compiled locks by digest, accepts immutable Git commits or bounded ZIP uploads through a tenant-authenticated API, and publishes the same audit bundle through renewable at-least-once worker leases. Docker Compose and Helm packaging are included; Kubernetes workers have a default-deny network policy.

The first distributed queue uses shared filesystem storage. Kubernetes custom resources, object storage, OIDC, capability-aware placement, task-level fan-out, and exactly-once execution remain roadmap items.
