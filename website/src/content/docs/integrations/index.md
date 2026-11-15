---
title: Integrations
description: Implemented and planned security-tool adapters, with accurate development status.
sidebar:
  order: 1
---

Caphe adapters strictly validate configuration, build argument arrays, discover external versions, bound process output, parse JSON, normalize findings, and preserve raw evidence after successful parsing.

| Tool | Category | Status | Adapter ID |
| --- | --- | --- | --- |
| [Opengrep](./opengrep/) | SAST | **Available** | `scanner.opengrep` |
| [Syft](./syft/) | SBOM | **Available** | `scanner.syft` |
| [Grype](./grype/) | SCA | **Available** | `scanner.grype` |
| [Gitleaks](./gitleaks/) | Secrets | **Available** | `scanner.gitleaks` |
| OPA | Policy | Planned | — |
| OSV-Scanner | SCA | Planned | — |
| Checkov | IaC | Planned | — |
| Kubescape | Kubernetes | Planned | — |

External output is capped at 64 MiB per invocation and stderr at 1 MiB. Version-specific fixture parsing is unit tested; CI against pinned real binaries is still required.

## Adding an adapter

Implement the Go `internal/adapters.Adapter` interface with a fixed ID and contract version, strictly validate JSON configuration, construct typed arguments without a shell, preserve raw output, and register the adapter in `DefaultRegistry`. Dynamic Go plugins are intentionally unsupported.
