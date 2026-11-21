.PHONY: build install uninstall install-tools tools-install test test-e2e test-e2e-real vet check demo

CAPHE_CACHE ?= $(if $(XDG_CACHE_HOME),$(XDG_CACHE_HOME),$(HOME)/.cache)/caphe
CAPHE_BIN ?= $(CAPHE_CACHE)/bin
TOOLS ?= poutine,actionlint,syft,grype,gitleaks,llama.cpp

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
