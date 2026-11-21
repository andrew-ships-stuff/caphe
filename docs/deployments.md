# Local cluster deployments

Caphe has an authenticated HTTP job API, queue workers, and an embedded
security workbench UI served by `caphe ui` (see [Workbench](#workbench)).
The website is documentation, not a cluster console. These deployments run the
real cluster image, installed scanners, bundled CPU runtime, and model. AI remains
operator-controlled and hypothesis-only. A successful job does not imply complete
scanner coverage: inspect the bundle's coverage and task statuses.

## Prerequisites and credentials

Use the repository's required Go toolchain, Docker with Compose, curl, and Python 3.
Kubernetes additionally needs kubectl, Minikube, and Helm 3. The verified local
configuration uses Docker Desktop 29.2.1 (arm64), Minikube 1.38.1, Kubernetes
v1.35.1, and Helm 3.17.3. Helm was downloaded from get.helm.sh and checked against
its release SHA-256 before execution, then installed at `~/.cache/caphe/bin/helm`.
Add that directory to `PATH` for the Helm commands below. Existing Docker, kubectl,
and Minikube installations were reused.

Generate two local tenant credentials for the cross-tenant integration tests
(refuses to overwrite an existing file), then build both images:

```bash
make deploy-auth
make images
```

The `make deploy-compose`, `make deploy-swarm`, and `make deploy-k8s` targets
build these images automatically.

`auth.json` is Git-ignored and excluded from the Docker build context. Tests read
it directly without putting bearer tokens in command arguments. If it already
exists, supply a file with two distinct configured tenants via
`CAPHE_TEST_AUTH_FILE=/absolute/path`. The servers must use those same credentials.

## Workbench

`caphe ui` serves the embedded workbench and same-origin-proxies `/api/` to the
fixed cluster API (`--api`, default `http://127.0.0.1:8787`). Bearer tokens stay
in the browser; the proxy strips ambient cookies and origins. Run it locally:

```bash
make build
./bin/caphe ui                       # http://127.0.0.1:3000
```

Tests: `go test ./internal/workbench` (proxy, boundary, import verification) and
`node --test tests/workbench` (pure model logic). The UI brand mark is derived
from `assets/caphe_simple_logo.png` and embedded as `caphe-mark.png`. Triage
notes and saved views are browser-local and labeled as such; AI output stays
hypothesis-labeled. The workbench never talks to a cluster directly — only
through its own same-origin `/api` proxy.

## 1. Docker Swarm

This configuration is for **one local manager**: both services use its named
volume. It is not a multi-node storage design. Unlike Compose, Swarm's published
ports bind all host interfaces; ports 8788 and 3003 are for local development
only. Remote access needs TLS termination and an appropriate host firewall.

```bash
make deploy-swarm                 # inits Swarm when inactive, builds images, deploys
docker stack services caphe-local
curl --fail http://127.0.0.1:8788/healthz
curl --fail http://127.0.0.1:3003/healthz   # workbench
make integration-swarm-tests
```

Wait for all three services to show 1/1 replicas before testing. `stack deploy` does
not build images; `--resolve-image never` uses the explicitly built local image.
The API and worker use different networks. The worker's internal overlay has no
external route, no published ports, and no API attachment. Keep one worker in
this local stack: an internal overlay permits communication between peers, so it
is not equivalent to per-worker network namespaces with no interfaces. Compose
provides the stricter `network_mode: none`; Kubernetes denies worker ingress and
egress through NetworkPolicy.

Swarm secrets are immutable. To rotate these local credentials, remove the stack,
wait for its services and secret to disappear, and recreate it with the new file.
The named queue volume survives stack removal.

## 2. Docker Compose

```bash
make deploy-compose               # builds images, then compose up -d --no-build
curl --fail http://127.0.0.1:8787/healthz
curl --fail http://127.0.0.1:3000/healthz   # workbench at http://127.0.0.1:3000
make integration-docker-compose-tests
```

The API and workbench bind host loopback; workers have no network. This uses a separate queue
volume from Swarm, so both can run concurrently. Each AI worker uses about 1.35 GiB
at idle in the verified environment. Budget additional memory for scanners.

## 3. Local Kubernetes

Use a dedicated profile and explicit context so another project's cluster remains
untouched. Allocate at least 6 GiB to this Minikube VM and enough Docker Desktop
memory for any simultaneously running Compose/Swarm workers.

```bash
make deploy-k8s                   # minikube start, image load, namespace/Secret bootstrap, helm upgrade
make integration-k8s-tests
```

`deploy-k8s` is idempotent: it reuses the profile, namespace, and Secret, and
reloads images on every run. Override the tool paths or names with `HELM=`,
`MINIKUBE=`, `KUBECTL=`, `CAPHE_K8S_PROFILE=`, `CAPHE_K8S_CONTEXT=`, or
`CAPHE_K8S_NAMESPACE=`. Rotate credentials with `make k8s-secret` (recreates the
Secret and restarts the API, which is required to reload authentication).

The test starts and cleans up its own loopback port-forward on 18787. To use the
API interactively, keep this command running in another terminal:

```bash
make api-forward   # keep running; then, with CAPHE_CLUSTER_TOKEN set:
caphe cluster workflows --endpoint http://127.0.0.1:18787
make ui-forward    # workbench at http://127.0.0.1:3000 (stop 'make ui' first)
```

Minikube's standard provisioner supports node-local `ReadWriteOnce`, not shared
multi-node storage. Multiple pods on the single node can use this PVC. The normal
chart retains `ReadWriteMany` for deployments spanning nodes. Do not use the local
values file for a multi-node cluster.

A NetworkPolicy object alone is not enforcement. This profile explicitly uses
Calico, following the [Minikube network policy guidance](https://minikube.sigs.k8s.io/docs/handbook/network_policy/).
The integration script proves the API Service is reachable from the API pod and
then verifies that the worker cannot connect to that same destination.

## Integration coverage and learnings

The three `make integration-*-tests` targets run against already deployed services;
they fail if the deployment or credentials are missing. The default `go test ./...`
skips this external suite unless `CAPHE_TEST_ENDPOINT` is supplied. Docker tests
also check worker network denial against a reachable API container. Kubernetes
tests wait for Deployment rollouts and check network denial before forwarding.

The common real-HTTP suite verifies health, missing/invalid authentication,
workflow registration, unknown workflow rejection, resource admission, denied
network requests, strict submission JSON, malformed ZIP rejection, archive upload,
worker completion, tenant isolation for jobs and bundles, executed workflow identity,
and a downloaded bundle's cryptographic digest. AI recommendations must remain
hypotheses. The archive includes a synthetic npm lockfile; no dependencies are downloaded.
Syft, Gitleaks, and Poutine must actually succeed. The suite does not exercise Git
acquisition, every scanner's finding parser, or model quality; those have separate
suites.

The first Swarm upload failed even though health was green: short-form `tmpfs`
was ignored by stack deployment, making `/tmp` read-only. Explicit `type: tmpfs`
volume mounts fixed API uploads and worker scratch space. Keep read-only root
filesystems and writable bounded temporary mounts together. Docker stack syntax
is not interchangeable with Compose syntax; see [Swarm networking](https://docs.docker.com/engine/swarm/networking/).

The first Kubernetes fixture took about 31 seconds because Syft's startup update
check waited on silently dropped traffic. Disabling automatic update checks cut
the same job to about one second. Workers now set `SYFT_CHECK_FOR_APP_UPDATE=false`,
`GRYPE_CHECK_FOR_APP_UPDATE=false`, and `GRYPE_DB_AUTO_UPDATE=false` in all three
deployments. See the [Syft configuration reference](https://oss.anchore.com/docs/reference/syft/configuration/)
and [Grype configuration reference](https://oss.anchore.com/docs/reference/grype/configuration/).
A usable offline Grype database must be provisioned separately; this image does
not include one, so dependency vulnerability coverage remains incomplete. Opengrep
is absent and is reported as skipped. We also observed that a README-only scan
produces a Syft SBOM without a `components` array, which the current adapter rejects;
that parser limitation is separate from deployment readiness. The integration
fixture includes a package lock and requires successful SBOM generation.

Go's `FileServer` strips `Cache-Control` from error responses, so the workbench
applies its security headers in a `WriteHeader`/`Write` wrapper instead of only
before delegation; otherwise 404s ship without `no-store`.

Verified on 2026-11-20: all three deployed integration targets passed with Syft,
Gitleaks, and Poutine successful, Opengrep skipped, and Grype explicitly failed for
missing offline database coverage. `gofmt -l .`, `go vet ./...`, `go test ./...`,
Helm lint, Compose configuration validation, and Swarm configuration validation
also passed. The workbench UI (`caphe ui`, `internal/workbench`, the UI image and
its Swarm/Compose/Helm services) landed with this deployment work; its Go and
model tests pass locally. The website and README still need a section on
launching the workbench.

## Inspect and stop

```bash
docker service logs caphe-local_worker
docker compose -p caphe-local-compose -f deployments/docker/compose.yaml logs worker
kubectl --context caphe-local -n caphe-local get pods,pvc,networkpolicy
kubectl --context caphe-local -n caphe-local logs deployment/caphe-worker

# Stop services while preserving queues:
make down-swarm      # removes the stack; the named volume survives
make down-compose    # compose stop, not down
make down-k8s
```

Do not remove volumes or the Minikube profile unless you intend to discard its jobs.
No Swarm leave, global Docker prune, or changes to other Kubernetes contexts are
needed for this workflow.
