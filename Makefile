GO ?= go
CLANG ?= clang++
LLVM_BIN ?=
LLVM_LIB ?=
GO_FUZZ_TAGS ?= libfuzzer
GO_FUZZ_GCFLAGS ?= -gcflags=all=-d=libfuzzer

BUILD := build
GO_ARCHIVE := $(BUILD)/libmtafuzz.a

.PHONY: all build fuzz-build fuzz-smoke test acceptance clean

all: build

build: $(BUILD)/mountaudit

$(BUILD)/mountaudit:
	mkdir -p $(BUILD)
	CGO_ENABLED=1 $(GO) build -o $@ ./cmd/mountaudit

$(GO_ARCHIVE):
	mkdir -p $(BUILD)
	CGO_ENABLED=1 $(GO) build -tags=$(GO_FUZZ_TAGS) $(GO_FUZZ_GCFLAGS) \
		-buildmode=c-archive -o $@ ./fuzz/go_fuzz_bridge

fuzz-build: $(BUILD)/mtafuzz

$(BUILD)/mtafuzz: fuzz/harness.cc $(GO_ARCHIVE)
	$(CLANG) -std=c++17 -g -O1 -fsanitize=fuzzer -I$(BUILD) \
		fuzz/harness.cc $(GO_ARCHIVE) -o $@ -lpthread -ldl -lm

fuzz-smoke: $(BUILD)/mtafuzz
	mkdir -p $(BUILD)/corpus
	cp testdata/original/container-mount-capture.v1.txt $(BUILD)/corpus/.seed
	mv -f $(BUILD)/corpus/.seed $(BUILD)/corpus/seed
	LD_LIBRARY_PATH=$(LLVM_LIB) $(BUILD)/mtafuzz \
		-runs=1000 -max_len=4096 $(BUILD)/corpus

test:
	CGO_ENABLED=1 $(GO) test ./...

acceptance: build test
	scripts/acceptance.sh

clean:
	$(RM) -r $(BUILD)
