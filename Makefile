SHELL := /bin/bash
ROOT := $(CURDIR)
FUZZ_SECONDS ?= 10
GO_SOURCES := $(shell find cmd internal fuzz -name '*.go') go.mod go.sum

include scripts/env.mk

.PHONY: all build fuzz clean FORCE

all: build

build: FORCE
	$(MAKE) build/dfexp build/df_fuzzer

FORCE:

build/dfexp: $(GO_SOURCES)
	mkdir -p build
	go build -o build/dfexp ./cmd/dfexp

build/libdfcodec.so: $(GO_SOURCES)
	mkdir -p build
	go build -buildmode=c-shared -o build/libdfcodec.so ./fuzz

build/df_fuzzer: build/libdfcodec.so fuzz/harness/harness.c
	clang -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address \
		-Ibuild fuzz/harness/harness.c -Lbuild -ldfcodec \
		-Wl,-rpath,'$$ORIGIN' -o build/df_fuzzer

fuzz: build/df_fuzzer
	mkdir -p artifacts/evidence/fuzz/seed artifacts/evidence/fuzz/corpus
	./build/dfexp seed --out artifacts/evidence/fuzz/seed
	cp --update=none artifacts/evidence/fuzz/seed/* artifacts/evidence/fuzz/corpus/
	set +e; \
	./build/df_fuzzer -dict=fuzz/df.dict -max_total_time=$(FUZZ_SECONDS) \
		-rss_limit_mb=2048 -artifact_prefix=artifacts/evidence/fuzz/ \
		artifacts/evidence/fuzz/seed artifacts/evidence/fuzz/corpus \
		>artifacts/evidence/fuzz/fuzzer.log 2>&1; \
	echo $$? >artifacts/evidence/fuzz/exit_code

clean:
	rm -rf build

