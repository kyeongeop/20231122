GO ?= go

.PHONY: build test fuzz fuzz-smoke vet fmt clean

build:
	$(GO) build -o bin/idorfix ./cmd/idorfix

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

# Builds the libFuzzer binary through cgo c-archive + clang.
fuzz:
	./internal/fuzz/build.sh

# Short bounded fuzz run used as a smoke test.
fuzz-smoke:
	$(GO) test ./internal/fuzz -run='^$$' -fuzz=FuzzTarget -fuzztime=5s

clean:
	find bin build -type f -delete 2>/dev/null || true
