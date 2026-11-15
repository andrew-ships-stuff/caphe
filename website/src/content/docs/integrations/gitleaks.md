---
title: Gitleaks
description: Available secret-scanning adapter behavior, redaction, and limitations.
sidebar:
  order: 5
---

**Status:** Available · **Adapter:** `scanner.gitleaks`

The adapter uses Gitleaks JSON report mode with `--redact` and requires no configuration in the default workflow.

```yaml
- id: secrets
  uses: scanner.gitleaks
  optional: true
```

Caphe additionally excludes fields named `secret`, `match`, and `entropy` from normalized properties. Findings retain rule, description, file, start line, severity, fingerprint, and provenance.

Redaction reduces accidental disclosure but does not make all scanner output safe to publish. Restrict access to raw artifacts and generated reports.
