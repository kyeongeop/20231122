# Cookie attribute audit tool - build & test entry points.
# Expects the rootless toolchain to be active: source scripts/env.sh

GO ?= go
CLANG ?= clang-18
BUILD_DIR := build
FUZZ_SRC := fuzz/cookie_audit_fuzz.c

.PHONY: all ckaudit fuzz plain test vet clean fmt

all: ckaudit fuzz plain

ckaudit:
	$(GO) build -o $(BUILD_DIR)/ckaudit ./cmd/ckaudit

fuzz:
	$(CLANG) -g -O1 -fsanitize=address,undefined,fuzzer \
		-fno-omit-frame-pointer -DCK_NO_MAIN=1 \
		-o $(BUILD_DIR)/cookie_audit_fuzz $(FUZZ_SRC)

plain:
	$(CLANG) -g -O1 -fsanitize=address,undefined \
		-fno-omit-frame-pointer \
		-o $(BUILD_DIR)/cookie_audit_plain $(FUZZ_SRC)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -f $(BUILD_DIR)/ckaudit $(BUILD_DIR)/cookie_audit_fuzz $(BUILD_DIR)/cookie_audit_plain
