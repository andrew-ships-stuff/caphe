---
title: Security workbench
description: Run caphe's installed investigation interface locally or beside cluster workers.
---

The security workbench is part of the installed `caphe` product. This documentation
site is its introduction, not the application itself.

## Run on your laptop

```bash
caphe ui
```

Open `http://127.0.0.1:3000`. The embedded interface requires no Node runtime or
external font/CDN connection. It opens a clearly labeled sample workspace. Import
a completed `caphe-audit.json` to investigate local results; the server verifies
the bundle's schema and content digest before displaying it.

To work with an existing cluster API:

```bash
caphe ui --listen 127.0.0.1:3000 --api http://127.0.0.1:8787
```

Choose **Connect API** and enter a tenant token. Tokens stay in tab memory and are
cleared on reload or disconnect. The UI uses a fixed same-origin API proxy; it
does not bypass the cluster's authentication or tenant boundaries.

## Deploy beside the API

From a source checkout:

```bash
make deploy-auth
make deploy-compose
```

The UI is available at `http://127.0.0.1:3000`; the API at
`http://127.0.0.1:8787`. The UI, API, and worker run in the same Compose project.

For a dedicated local Kubernetes cluster:

```bash
make deploy-k8s
make ui-forward
```

Open the local address printed by the port-forward command. The Helm chart runs
the workbench as a separate Deployment and Service alongside the API and worker.
See the repository's [deployment guide](https://github.com/andrew-ships-stuff/caphe/blob/main/docs/deployments.md)
for Swarm, storage, network enforcement, credential setup, and shutdown commands.

## Investigation workflow

Start in the Attention Queue. Filter by severity, repository, package, CVE, new
observations, confirmed routes, available fixes, or resolved observations. Open a
finding to follow its dossier through evidence, judgment, remediation, and history.
The dossier is resizable on desktop and uses the available width on smaller screens.

- Use **Runs** to select an analysis and load a comparison baseline.
- Submit a repository ZIP with **New analysis**. Operators control the registered workflow and worker settings.
- Use **Ctrl/Command K** for the command palette, **/** to search, **J/K** to move between findings, and **?** for keyboard help.
- Export filtered findings or copy a case note for a pull request.
- Save views and triage annotations in this browser. These are not shared team records and do not modify immutable evidence or server policy.

## Evidence boundaries

Scanner findings remain distinct from local-model hypotheses. A package match is
not proof of exploitability; absent independent evidence, live reachability remains
**Not established**. Priority uses explicit severity, confirmed routes, and available
fixes, never an unexplained AI score.

A finding missing from a comparison scan is not independently verified as fixed.
Review scanner coverage in both runs. Missing or failed scanners cannot establish
the absence of vulnerabilities. Sample repository relationships and reachability
annotations are illustrative and are never merged into live results.
