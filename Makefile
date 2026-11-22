GO ?= go
CLANGXX ?= clang++

.PHONY: build test fuzz demo verify clean

build:
	$(GO) build -o build/replayctl ./cmd/replayctl

test:
	$(GO) test ./...

fuzz:
	RUNS=20000 ./scripts/run_libfuzzer.sh

demo:
	./scripts/demo.sh

verify:
	$(GO) run ./cmd/replayctl verify --bundle artifacts/review/baseline/bundle

clean:
	rm -rf build
