GO ?= go
WORKSPACE ?= evidence
RUN_ID ?= uid6-0044-replay
FUZZ ?= auto
FUZZ_RUNS ?= 2000
CLANGXX ?= clang++

.PHONY: build test run demo verify fuzz clean

build:
	$(GO) build -trimpath -o dist/cacheleak .

test:
	$(GO) test ./... -count=1

run:
	$(GO) run . run --workspace $(WORKSPACE) --fuzz $(FUZZ) \
		--fuzz-runs $(FUZZ_RUNS) --clangxx $(CLANGXX)

demo:
	@test ! -e .cacheleak-demo || \
		(echo "refusing to overwrite existing demo workspace: .cacheleak-demo"; exit 1)
	$(GO) run . run --workspace .cacheleak-demo --run-id demo-0044 \
		--fuzz $(FUZZ) --fuzz-runs $(FUZZ_RUNS) --clangxx $(CLANGXX)

verify:
	$(GO) run . verify --workspace $(WORKSPACE) --run-id $(RUN_ID)

fuzz:
	cd fuzz && FUZZ_RUNS=$(FUZZ_RUNS) ./run.sh

clean:
	$(GO) clean
	rm -rf dist .cacheleak-demo
