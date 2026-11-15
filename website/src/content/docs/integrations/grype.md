---
title: Grype
description: Available dependency-vulnerability adapter configuration, outputs, and limitations.
sidebar:
  order: 4
---

**Status:** Available · **Adapter:** `scanner.grype`

Grype consumes an SBOM artifact where supplied and normalizes vulnerability matches while retaining each original match object.

```yaml
- id: dependencies
  uses: scanner.grype
  needs: [sbom]
  with:
    input: "${tasks.sbom.outputs.sbom}"
```

Normalized findings include vulnerability ID, affected package and version, scanner severity, fingerprint, and provenance. A scanner match is an observation, not independent proof of reachability or exploitability.

Typed `${tasks.*}` output-schema checking is still on the roadmap; use the shipped default workflow as the supported reference.
