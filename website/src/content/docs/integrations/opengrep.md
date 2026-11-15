---
title: Opengrep
description: Available SAST adapter configuration, inputs, outputs, and limitations.
sidebar:
  order: 2
---

**Status:** Available · **Adapter:** `scanner.opengrep`

The adapter discovers `opengrep`, runs `scan --json --config RULESET .`, parses result locations and severity, and preserves each complete result object in normalized properties.

```yaml
- id: sast
  uses: scanner.opengrep
  with:
    ruleset: .caphe/security.yaml
```

Install Opengrep from its upstream project and confirm discovery with `caphe tools doctor`. The ruleset may be a local path or a scanner-supported identifier. Network behavior belongs to the scanner and environment; Caphe's recorded `network: restricted` policy does not yet enforce egress.

Normalized output includes tool, rule ID, title, severity, path, line, deterministic fingerprint, and provenance. Source snippets in scanner properties may be sensitive.
