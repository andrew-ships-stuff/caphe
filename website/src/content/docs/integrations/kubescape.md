---
title: Kubescape
description: Available Kubernetes posture adapter behavior and offline artifacts.
---

**Status:** Available · **Adapter:** `scanner.kubescape`

The adapter performs a local repository scan and requests SARIF, preserving each complete result while normalizing its rule, message, severity, and source location.

```yaml
- id: kubernetes
  uses: scanner.kubescape
  optional: true
  with:
    useArtifactsFrom: .kubescape
```

Without `useArtifactsFrom`, Kubescape controls how its policy artifacts are obtained and may use the network. Point the setting at a relative, pre-downloaded artifact directory for an offline scan. This adapter scans repository files; it does not select or contact a live Kubernetes cluster.
