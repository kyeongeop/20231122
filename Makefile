GO ?= $(shell command -v go 2>/dev/null || \
	{ test -x /home/hj/go/bin/go && printf '%s' /home/hj/go/bin/go; } || printf go)
CLANG ?= $(shell command -v clang 2>/dev/null || \
	{ test -x /home/hj/toolchain/llvm-root/usr/lib/llvm-21/bin/clang && \
	printf '%s' /home/hj/toolchain/llvm-root/usr/lib/llvm-21/bin/clang; } || printf clang)
GOFLAGS ?= -trimpath
BUILD_DIR ?= build

.PHONY: all build harness test integration demo clean

all: build harness

build:
	mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/auditfix ./cmd/auditfix

harness:
	mkdir -p $(BUILD_DIR)
	$(CLANG) -std=c++17 -O1 -g -fsanitize=fuzzer,address,undefined \
		-fno-omit-frame-pointer -Ifuzz fuzz/harness.cc \
		-o $(BUILD_DIR)/auditfix_harness

test: build harness
	$(GO) test ./...
	./scripts/integration.sh

integration: all
	./scripts/integration.sh

demo: all
	./$(BUILD_DIR)/auditfix demo --dir demo --force \
		--harness $(BUILD_DIR)/auditfix_harness

clean:
	rm -rf $(BUILD_DIR)
