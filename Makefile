GO ?= go
CLANG ?= clang
FUZZ_TARGET := build/seed_target
DB := var/demo/audit.db
EVIDENCE := var/demo/evidence

.PHONY: all test fuzz-build demo demo-legacy verify

all: test

$(FUZZ_TARGET): fuzz/seed_target.c
	mkdir -p build
	$(CLANG) -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -o $@ $<

fuzz-build: $(FUZZ_TARGET)

test: fuzz-build
	$(GO) test ./...

demo: fuzz-build
	mkdir -p var/demo
	$(GO) run ./cmd/seedreview init --db $(DB) --evidence $(EVIDENCE)
	$(GO) run ./cmd/seedreview replay --db $(DB) --evidence $(EVIDENCE) --manifest testdata/recovery-v2.json
	$(GO) run ./cmd/seedreview report --db $(DB) --evidence $(EVIDENCE) --run 1 --format markdown

demo-legacy: fuzz-build
	mkdir -p var/demo-legacy
	$(GO) run ./cmd/seedreview init --db var/demo-legacy/audit.db --evidence var/demo-legacy/evidence
	$(GO) run ./cmd/seedreview replay --db var/demo-legacy/audit.db --evidence var/demo-legacy/evidence --manifest testdata/recovery-v1.json
	$(GO) run ./cmd/seedreview report --db var/demo-legacy/audit.db --evidence var/demo-legacy/evidence --run 1 --format markdown

verify:
	$(GO) run ./cmd/seedreview verify --db $(DB) --evidence $(EVIDENCE)
