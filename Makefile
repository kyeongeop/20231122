GO ?= go
CLANGXX ?= clang++

.PHONY: build test fuzz demo verify

build:
	$(GO) build -o build/migrationctl ./cmd/migrationctl

test:
	$(GO) test ./...

fuzz:
	RUNS=20000 ./scripts/run_libfuzzer.sh

demo:
	$(GO) run ./cmd/migrationctl demo --out artifacts/review

verify:
	$(GO) run ./cmd/migrationctl verify --evidence artifacts/review/evidence.sqlite
