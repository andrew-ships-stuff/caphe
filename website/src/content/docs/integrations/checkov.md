---
title: Checkov
description: Available infrastructure-as-code adapter configuration and output handling.
---

**Status:** Available · **Adapter:** `scanner.checkov`

The adapter scans the target directory, requests JSON, and normalizes every failed check from both single- and multi-framework reports. `framework` is optional and is passed as one explicit argument.

```yaml
- id: infrastructure
  uses: scanner.checkov
  optional: true
  with:
    framework: terraform,kubernetes
```

Caphe enables Checkov soft-fail behavior so policy violations are parsed as findings instead of failing the task. Result upload and policy downloads are disabled. Open-source reports may omit severity; those findings retain `unknown` severity rather than inventing one.
