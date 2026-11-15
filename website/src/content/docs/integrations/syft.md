---
title: Syft
description: Available SBOM adapter configuration, outputs, and limitations.
sidebar:
  order: 3
---

**Status:** Available · **Adapter:** `scanner.syft`

Syft produces inventory evidence, not vulnerability findings. Caphe runs the target scan and retains the raw SBOM. Supported configured output formats are CycloneDX JSON and Syft JSON.

```yaml
- id: sbom
  uses: scanner.syft
  with:
    outputFormat: cyclonedx-json
```

The normalized result records package count metadata. Rich package-to-service and image-to-workload graph relationships remain roadmap work.

Install Syft from Anchore's upstream releases, pin its version in CI, and retain the Caphe execution manifest recording the detected binary version.
