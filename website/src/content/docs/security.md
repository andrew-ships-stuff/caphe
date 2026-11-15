---
title: Security model
description: Caphe trust boundaries, privacy properties, prompt-injection controls, and current limitations.
---

import { Aside } from '@astrojs/starlight/components';

Caphe is local-first, not magically isolated. Workflows, repositories, scanners, model output, and reports cross distinct trust boundaries.

## Data privacy

The deterministic engine runs locally and does not require a hosted API. Raw scanner output is stored in the local artifact directory; normalized findings and graph records are stored in local SQLite. Neither is encrypted at rest. Reports and model prompts may contain source excerpts and require the same handling as the scanned repository.

## Untrusted repositories

The compiler rejects arbitrary executable and command settings. Built-in workflows do not run repository build hooks or active tests. Scanner processes still run with the invoking user's ordinary filesystem and process privileges, and each scanner decides how it handles symlinks inside the target.

<Aside type="danger">When scanning hostile content, use a nonprivileged container or dedicated sandbox. Do not mount a container-engine socket or grant cluster-admin.</Aside>

The workflow field `network: restricted` is recorded but is **not** enforced as an operating-system egress control in the current snapshot.

## Scanner isolation and secrets

Caphe passes an executable and argument array directly instead of using a shell. It applies timeouts and bounded capture: scanner stdout is capped at 64 MiB and stderr at 1 MiB. These are availability controls, not a filesystem, syscall, process, memory, or network sandbox.

Gitleaks runs in redacted JSON mode. Caphe additionally removes `secret`, `match`, and `entropy` fields from normalized properties. Checkov runs in compact mode and has source blocks and evaluated values removed before persistence by default; `includeSensitiveOutput: true` deliberately disables that protection. Raw output from other scanners and source excerpts can still contain sensitive material.

## Prompt-injection resistance

Repository and finding content is wrapped as untrusted evidence, never instructions. The inference system prompt forbids commands, URLs, or prose outside the supplied schema. Endpoints must be loopback. Responses have token, time, and byte bounds and are parsed with unknown fields rejected.

These controls reduce the model's authority; they do not make language-model output correct. Inference cannot add tasks, construct commands, select runtime control flow, or confirm its own hypothesis.

## Verification trust model

A scanner observation confirms only that the scanner reported it. A deterministic relationship confirms only what its derivation rule establishes. A model hypothesis remains `hypothesized` until an independent strategy supports or contradicts it. Related weaknesses do not by themselves prove an exploitable attack path.

## Vulnerability disclosure

The repository does not currently contain a dedicated `SECURITY.md` disclosure policy. Avoid posting exploit details publicly before maintainers provide a private channel; open a minimal GitHub issue requesting a security contact without sensitive reproduction details.

## Known limitations

- No strong subprocess sandbox or OS-enforced network restriction.
- Local SQLite and artifacts are permission-restricted but unencrypted.
- Managed model and llama.cpp provisioning are absent.
- Broad verification strategies and cross-domain graph correlation are incomplete.
- Real-scanner pinned CI and Windows-specific hardening remain roadmap work.
