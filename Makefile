.PHONY: help build install uninstall install-tools tools-install test test-e2e test-e2e-real vet check demo

CAPHE_CACHE ?= $(if $(XDG_CACHE_HOME),$(XDG_CACHE_HOME),$(HOME)/.cache)/caphe
CAPHE_BIN ?= $(CAPHE_CACHE)/bin
TOOLS ?= poutine,actionlint,syft,grype,gitleaks,llama.cpp

help:
	@echo 'build/test'
	@echo '  make build                     build ./bin/caphe'
	@echo '  make test | vet | check        go test, go vet, both + build'
	@echo '  make demo                      scan examples/vulnerable-go'
	@echo '  make install-tools             install pinned managed tools'
	@echo ''
	@echo 'ui'
	@echo '  make ui                        run the workbench at http://127.0.0.1:3000'
	@echo '  make images                    build caphe-cluster:local + caphe-workbench:local'
	@echo '  make deploy-auth               create deployments/docker/auth.json (never overwrites)'
	@echo '  make token                     print tenant tokens for the cluster CLI/UI'
	@echo ''
	@echo 'deploy                              workbench    api'
	@echo '  make deploy-compose            :3000          :8787     down: make down-compose'
	@echo '  make deploy-swarm              :3003          :8788     down: make down-swarm'
	@echo '  make deploy-k8s                make ui-forward          down: make down-k8s'
	@echo '                                   make api-forward (:18787)'
	@echo '  make k8s-secret                rotate credentials + restart API'
	@echo '  make k8s-context               kubectl -> caphe-local/caphe-local (undo: make k8s-restore)'
	@echo '  make k8s-pods | k8s-logs       pods overview / logs of deploy (component=caphe-api|caphe-worker|caphe-ui)'
	@echo ''
	@echo 'integration (run after deploying; require the matching stack up)'
	@echo '  make integration-docker-compose-tests | integration-swarm-tests | integration-k8s-tests'
	@echo ''
	@echo 'Overrides: HELM= MINIKUBE= KUBECTL= CAPHE_K8S_PROFILE/CONTEXT/NAMESPACE= CAPHE_COMPOSE_PROJECT= CAPHE_SWARM_STACK= CAPHE_TEST_AUTH_FILE='

build:
	go build -o bin/caphe ./cmd/caphe

build-release:
	go run ./scripts/embed-runtime
	go build -tags bundled -trimpath -o bin/caphe ./cmd/caphe

install: build-release install-tools
	@mkdir -p "$(CAPHE_BIN)" "$(CAPHE_CACHE)/libexec"
	install -m 0755 bin/caphe "$(CAPHE_BIN)/caphe"
	install -m 0755 scripts/install-tools.sh "$(CAPHE_CACHE)/libexec/install-tools.sh"
	@echo "Installed to $(CAPHE_BIN)/caphe"
	@echo "Caphe automatically discovers managed tools in $(CAPHE_BIN)."

uninstall:
	@unlink "$(CAPHE_BIN)/caphe" 2>/dev/null || true
	@unlink "$(CAPHE_CACHE)/libexec/install-tools.sh" 2>/dev/null || true
	@echo "Removed $(CAPHE_BIN)/caphe; delete $(CAPHE_CACHE) to remove all Caphe-managed state and tools."

install-tools tools-install:
	bash scripts/install-tools.sh --bin-dir "$(CAPHE_BIN)" --tools "$(TOOLS)"

test:
	go test ./...

test-e2e:
	go test ./tests/e2e -count=1 -v

test-e2e-real: build
	bash scripts/e2e-real.sh ./bin/caphe

vet:
	go vet ./...

check: test vet build

demo: build
	./bin/caphe scan examples/vulnerable-go --workflow caphe:demo-local

.PHONY: integration-docker-compose-tests integration-swarm-tests integration-k8s-tests
CAPHE_TEST_AUTH_FILE ?= $(CURDIR)/deployments/docker/auth.json

integration-docker-compose-tests:
	CAPHE_TEST_AUTH_FILE="$(CAPHE_TEST_AUTH_FILE)" bash scripts/integration-docker.sh compose

integration-swarm-tests:
	CAPHE_TEST_AUTH_FILE="$(CAPHE_TEST_AUTH_FILE)" bash scripts/integration-docker.sh swarm

integration-k8s-tests:
	CAPHE_TEST_AUTH_FILE="$(CAPHE_TEST_AUTH_FILE)" bash scripts/integration-k8s.sh

.PHONY: images deploy-auth token ui deploy-compose down-compose deploy-swarm down-swarm deploy-k8s down-k8s k8s-context k8s-restore k8s-secret k8s-pods k8s-logs api-forward ui-forward
CAPHE_COMPOSE_PROJECT ?= caphe-local-compose
CAPHE_SWARM_STACK ?= caphe-local
CAPHE_K8S_PROFILE ?= caphe-local
CAPHE_K8S_CONTEXT ?= caphe-local
CAPHE_K8S_NAMESPACE ?= caphe-local
HELM ?= $(if $(wildcard $(CAPHE_BIN)/helm),$(CAPHE_BIN)/helm,helm)
MINIKUBE ?= minikube
KUBECTL ?= kubectl

images:
	docker build -f deployments/docker/Dockerfile.cluster -t caphe-cluster:local .
	docker build -f deployments/docker/Dockerfile.ui -t caphe-workbench:local .

deploy-auth:
	@test -f "$(CAPHE_TEST_AUTH_FILE)" || python3 -c "import json,os,secrets; fd=os.open('$(CAPHE_TEST_AUTH_FILE)', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600); os.write(fd, json.dumps({'tokens':[{'tenant':t,'token':secrets.token_hex(32)} for t in ('development','integration-other')]}).encode()); os.close(fd); print('created $(CAPHE_TEST_AUTH_FILE)')"
	@echo "credentials: $(CAPHE_TEST_AUTH_FILE)"

token:
	@test -f "$(CAPHE_TEST_AUTH_FILE)" || { echo "run 'make deploy-auth' first" >&2; exit 1; }
	@python3 -c "import json; [print(t['tenant']+':', t['token']) for t in json.load(open('$(CAPHE_TEST_AUTH_FILE)'))['tokens']]"
	@echo 'export CAPHE_CLUSTER_TOKEN=<token>  # then: caphe cluster ... --endpoint http://127.0.0.1:18787 (make api-forward)'

ui: build
	./bin/caphe ui

deploy-compose: images
	docker compose -p $(CAPHE_COMPOSE_PROJECT) -f deployments/docker/compose.yaml up -d --no-build
	@echo "workbench: http://127.0.0.1:3000  api: http://127.0.0.1:8787"
	@echo "verify: make integration-docker-compose-tests (stop 'make ui' first if :3000 is taken)"

down-compose:
	docker compose -p $(CAPHE_COMPOSE_PROJECT) -f deployments/docker/compose.yaml stop

deploy-swarm: images
	@docker info --format '{{.Swarm.LocalNodeState}}' | grep -q active || docker swarm init
	docker stack deploy --resolve-image never -c deployments/docker/swarm.yaml $(CAPHE_SWARM_STACK)
	@echo "workbench: http://127.0.0.1:3003  api: http://127.0.0.1:8788 (published on all interfaces; local development only)"
	@echo "verify: make integration-swarm-tests"

down-swarm:
	docker stack rm $(CAPHE_SWARM_STACK)

deploy-k8s: images
	$(MINIKUBE) start -p $(CAPHE_K8S_PROFILE) --driver=docker --kubernetes-version=v1.35.1 --cni=calico --cpus=4 --memory=6144 --keep-context
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) create namespace $(CAPHE_K8S_NAMESPACE) --dry-run=client -o yaml | $(KUBECTL) --context $(CAPHE_K8S_CONTEXT) apply -f -
	@test -f "$(CAPHE_TEST_AUTH_FILE)" || { echo "run 'make deploy-auth' first" >&2; exit 1; }
	@$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) get secret caphe-auth >/dev/null 2>&1 || $(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) create secret generic caphe-auth --from-file=auth.json=$(CAPHE_TEST_AUTH_FILE)
	@echo "refreshing :local images (minikube image load skips existing tags unless removed first)"
	@$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) scale deploy caphe-api caphe-worker caphe-ui --replicas=0 >/dev/null 2>&1 || true
	@$(MINIKUBE) -p $(CAPHE_K8S_PROFILE) image rm caphe-cluster:local caphe-workbench:local >/dev/null 2>&1 || true
	$(MINIKUBE) -p $(CAPHE_K8S_PROFILE) image load caphe-cluster:local caphe-workbench:local
	$(HELM) --kube-context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) upgrade --install caphe deployments/helm/caphe -f deployments/helm/caphe/values-local.yaml --wait --timeout 3m
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) scale deploy caphe-api caphe-worker caphe-ui --replicas=1
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) rollout status deployment/caphe-api --timeout=180s
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) rollout status deployment/caphe-ui --timeout=120s
	@echo "workbench: make ui-forward  api: make api-forward"
	@echo "point kubectl at it: make k8s-context (undo: make k8s-restore)"
	@echo "verify: make integration-k8s-tests"

down-k8s:
	$(MINIKUBE) stop -p $(CAPHE_K8S_PROFILE)

k8s-context:
	$(KUBECTL) config use-context $(CAPHE_K8S_CONTEXT)
	$(KUBECTL) config set-context $(CAPHE_K8S_CONTEXT) --namespace=$(CAPHE_K8S_NAMESPACE)
	@echo "kubectl now targets $(CAPHE_K8S_CONTEXT)/$(CAPHE_K8S_NAMESPACE); restore with 'make k8s-restore'"

KUBECTL_PREV_CONTEXT ?= ctrllyric
k8s-restore:
	$(KUBECTL) config use-context $(KUBECTL_PREV_CONTEXT)

k8s-pods:
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) get pods,svc,pvc

component ?= caphe-api
k8s-logs:
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) logs deploy/$(component) --tail=50 -f

k8s-secret:
	@test -f "$(CAPHE_TEST_AUTH_FILE)" || { echo "run 'make deploy-auth' first" >&2; exit 1; }
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) delete secret caphe-auth --ignore-not-found
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) create secret generic caphe-auth --from-file=auth.json=$(CAPHE_TEST_AUTH_FILE)
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) rollout restart deployment/caphe-api

api-forward:
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) port-forward --address 127.0.0.1 service/caphe 18787:8787

ui-forward:
	$(KUBECTL) --context $(CAPHE_K8S_CONTEXT) -n $(CAPHE_K8S_NAMESPACE) port-forward --address 127.0.0.1 service/caphe-ui 3000:3000
