GO ?= $(shell command -v go 2>/dev/null || echo $(shell getent passwd $$(id -u) | cut -d: -f6)/.local/go/bin/go)

.PHONY: test demo verify fuzz fuzz-run

test:
	GOTOOLCHAIN=local $(GO) test ./...

demo:
	GOTOOLCHAIN=local $(GO) run ./cmd/taintlab demo --dir artifacts

verify:
	GOTOOLCHAIN=local $(GO) run ./cmd/taintlab verify-db --db artifacts/evidence.sqlite
	GOTOOLCHAIN=local $(GO) run ./cmd/taintlab verify-export --dir artifacts/export

fuzz:
	./fuzz/build.sh

fuzz-run:
	./fuzz/run.sh -runs=10000
