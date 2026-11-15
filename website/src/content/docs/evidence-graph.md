---
title: Evidence graph
description: How Caphe separates observed, derived, hypothesized, and verified security knowledge.
---

The graph keeps provenance and epistemic status explicit. Related records are not automatically equivalent to a confirmed vulnerability.

| Class | Meaning | Current state |
| --- | --- | --- |
| **Observed** | A scanner reported a fact, retained with raw output and source metadata. | Implemented for findings and SBOM metadata. |
| **Derived** | A deterministic rule connected exact evidence. | Implemented foundation for exact source-file references. |
| **Hypothesis** | A bounded model proposed a relationship requiring evidence. | Implemented for one invariant contract. |
| **Verification** | An independent strategy supported, contradicted, or could not resolve a hypothesis. | Types and adapter foundation exist; broader strategies are roadmap work. |

## Example relationships

```text
[Package: net/http] ──DEPENDS_ON──► [Service: checkout]
        │                                │
        └──SUPPORTS──► [Vulnerability]   └──DEPLOYED_AS──► [ContainerImage]
                                                              │
                                                              └──REFERENCES──► [Workload]
                                                                                   │
                                                                                   └──USES_IDENTITY──► [ServiceAccount]
```

Package, image, workload, identity, permission, trust-boundary, and verification node types are defined. The end-to-end correlation shown above describes the intended graph; current materialization is narrower and focuses on scanner observations plus exact source locations.

## Authorization hypothesis

```text
[Finding at handlers/order.go:84] ──SUPPORTS──► [Hypothesis]
                                                    │
                                                    └──VERIFIED_BY──► [Regression test]
                                                                           │
                                              supported / contradicted / inconclusive
```

The model may propose that an object-authorization property should hold at a code location. It must name required evidence and an allowlisted verification strategy. Until that strategy runs independently, the node remains `hypothesized`; it is not rendered as a confirmed scanner finding.

## Query the current graph

```bash
caphe findings list --json
caphe graph query --finding 'sha256:…' --json
caphe findings explain 'sha256:…' --json
```

Exact source locations and retained provenance are proof inputs. Similarity, proximity, or model confidence are not proof.
