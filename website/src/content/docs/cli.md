---
title: CLI reference
description: Commands and flags verified from the Caphe Cobra command tree.
---

This reference reflects the source command tree in the current `0.1.0-dev` snapshot.

## Global flags

| Flag | Default | Description |
| --- | --- | --- |
| `--data-dir PATH` | OS user config directory under `caphe` | State database and artifact directory. |
| `--json` | `false` | Emit stable machine-readable JSON instead of the terminal presentation. |
| `-h`, `--help` | — | Show command help. |

## Compile and execute

```text
caphe workflows list
caphe workflows validate WORKFLOW
caphe compile WORKFLOW [-o|--output workflow.lock.json]
caphe validate LOCKFILE
caphe run LOCKFILE [--target .] [--concurrency N]
caphe scan TARGET [--workflow FILE] [--concurrency N]
caphe audit [TARGET] [--workflow FILE] [--concurrency N]
```

`scan` compiles and runs in one process. With no `--workflow`, both `scan` and `audit` load the embedded `caphe:default` workflow. `audit` also correlates evidence and writes digest-pinned JSON, SARIF, Markdown, and HTML outputs. `run` validates a compiled lock before execution.

## Inspect the installation

| Command | Purpose |
| --- | --- |
| `caphe version` | Print Caphe, compiler, Go, OS, and architecture versions. |
| `caphe doctor` | Inspect storage, hardware, scanners, and loopback inference availability. |
| `caphe init` | Initialize local SQLite state and artifact storage. |
| `caphe hardware inspect` | Report CPU, memory, disk, container, and declared limit data. |
| `caphe tools list` | List detected registered scanner adapters. |
| `caphe tools doctor` | Inspect the same scanner detection information for diagnostics. |

The tool commands include Opengrep, Syft, Grype, Gitleaks, Poutine, OPA, OSV-Scanner, Checkov, and Kubescape. Detection does not install a tool or silently replace a missing executable.

Interactive output uses aligned sections and status marks: `✓` succeeded or available, `✗` failed or missing, `!` a finding that needs attention, and `○` skipped, optional, or inactive. Audit and workflow spinners are enabled only for a terminal, never for redirected output. Add `--json` to any status or inspection command for automation.

## Findings, graph, and reports

```text
caphe findings list
caphe findings explain FINDING_ID
caphe graph query --finding FINDING_ID
caphe report [--format table|json|sarif|html] [-o|--output -]
```

Reports read persisted findings. The default `table` format is human-readable. JSON and SARIF include structured records; HTML is a self-contained local report. `caphe report --json` selects JSON unless `--format` is explicitly provided.

## Optional inference

```text
caphe ai status
caphe ai models
caphe ai recommend
caphe ai doctor
caphe ai analyze --finding ID --model NAME --model-digest sha256:…
                 [--endpoint http://127.0.0.1:8080] [--timeout 60s]
```

`ai analyze` requires all three identity flags. It only accepts a loopback HTTP endpoint and stores schema-valid output as a hypothesis.

## Benchmarks

```text
caphe benchmark run [--iterations 1000]
```

This is a deterministic normalization smoke test. It explicitly reports unavailable correlation, AI, and verification baselines as `not_run`.

## Exit behavior

The compiled CLI exits `0` when a command completes successfully and `1` when command execution returns an error. On error it writes a line prefixed with `caphe:` to stderr. Individual scanners can produce partial task failure inside an execution manifest; use the command exit and manifest together.

## Shell completion

Cobra provides the generated `completion` command. Run `caphe completion --help` for supported shells and installation instructions for the built binary.
