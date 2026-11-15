.PHONY: build install uninstall tools-install test test-e2e test-e2e-real vet check demo

CAPHE_CACHE ?= $(HOME)/.cache/caphe
CAPHE_BIN ?= $(CAPHE_CACHE)/bin

build:
	go build -o bin/caphe ./cmd/caphe

install: build
	@mkdir -p "$(CAPHE_BIN)"
	install -m 0755 bin/caphe "$(CAPHE_BIN)/caphe"
	@echo "Installed to $(CAPHE_BIN)/caphe"
	@echo 'Add to your shell profile: export PATH="$(CAPHE_BIN):$$PATH"'

uninstall:
	@unlink "$(CAPHE_BIN)/caphe" 2>/dev/null || true
	@echo "Removed $(CAPHE_BIN)/caphe; delete $(CAPHE_CACHE) to remove all Caphe-managed state and tools."

tools-install:
	bash scripts/install-tools.sh --bin-dir "$(CAPHE_BIN)"

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
	./bin/caphe scan examples/vulnerable-go --workflow workflows/demo-local.yaml
