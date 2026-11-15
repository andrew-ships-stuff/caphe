---
title: Checkov
description: Available infrastructure-as-code adapter configuration and output handling.
---

**Status:** Available · **Adapter:** `scanner.checkov`

The adapter scans the target directory, requests JSON, and normalizes every failed check from both single- and multi-framework reports. `framework` is optional and is passed as one explicit argument. Caphe requests compact output and removes source blocks, connected-node data, and evaluated values before persistence.

```yaml
- id: infrastructure
  uses: scanner.checkov
  optional: true
  with:
    framework: terraform,kubernetes
```

Caphe enables Checkov soft-fail behavior so policy violations are parsed as findings instead of failing the task. Result upload and policy downloads are disabled. Open-source reports may omit severity; those findings retain `unknown` severity rather than inventing one.

Set `includeSensitiveOutput: true` only when full Checkov JSON is required. This disables Caphe's default redaction and can place repository source or credentials in raw artifacts and reports; protect the data directory and every exported bundle accordingly.
