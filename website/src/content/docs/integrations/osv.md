---
title: OSV-Scanner
description: Available dependency-vulnerability adapter behavior and offline mode.
---

**Status:** Available · **Adapter:** `scanner.osv`

The adapter recursively scans the target with OSV-Scanner's v2 `scan source` command and normalizes JSON vulnerabilities with their package and source metadata. OSV's documented exit code `1` means findings were present, so Caphe treats it as a successful scanner result.

```yaml
- id: osv
  uses: scanner.osv
  optional: true
  with:
    offline: true
```

Online mode is the default and may access OSV services. `offline: true` requires a local database downloaded in advance and prevents OSV-Scanner from downloading or updating it. Repository `osv-scanner.toml` files remain scanner-owned configuration.
