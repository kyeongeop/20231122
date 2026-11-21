GO ?= go

.PHONY: all test fuzz experiment query clean

all: test experiment

test:
	$(GO) test ./...

# libFuzzer-compatible fuzzing via Go's native fuzz engine (coverage-guided,
# AFL/libFuzzer style). Seed corpus lives in testdata/fuzz/FuzzMachine.
fuzz:
	$(GO) test ./internal/fsm/ -run='^$$' -fuzz=FuzzMachine -fuzztime=30s

experiment:
	$(GO) run ./cmd/experiment

query:
	$(GO) run ./cmd/dbquery

clean:
	$(GO) clean ./...
