---
title: OPA
description: Available Rego policy adapter configuration, result contract, and limitations.
---

**Status:** Available · **Adapter:** `scanner.opa`

The adapter runs `opa eval` with JSON output. `policy` and `query` are required; `input` is optional. Policy and input paths must be relative to the scan target and cannot traverse to a parent directory.

```yaml
- id: policy
  uses: scanner.opa
  with:
    policy: policy/deny.rego
    input: policy/input.json
    query: data.caphe.deny
```

The query may return a boolean, string, or collection of objects. Object violations may provide `id` (or `rule_id`/`code`), `message` (or `msg`/`title`), `severity` (or `level`), `path` (or `file`), and `line`. Other object fields remain in finding properties. A false boolean produces no finding.

Caphe does not supply a policy or infer a query. Keep Rego and input data under review like other workflow inputs.
