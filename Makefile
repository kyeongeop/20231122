# Toolchain. Override CLANG_DIR to point at an extracted LLVM release that
# ships the libFuzzer clang runtime (libclang_rt.fuzzer_no_main-*.a).
GO        ?= go
CLANG_DIR ?= /home/hj/.local/opt/clang-llvm-18
CLANG     ?= $(CLANG_DIR)/bin/clang
# Older Ubuntu releases need libtinfo.so.5 for the prebuilt clang 18 binary.
export LD_LIBRARY_PATH ?= /home/hj/.local/compat-libs
FUZZ_RT   := $(wildcard $(CLANG_DIR)/lib/clang/*/lib/x86_64-unknown-linux-gnu/libclang_rt.fuzzer_no_main.a)
LD_SCRIPT := bin/fuzzer_runtime.ld

V1_SNAPSHOT ?= snapshots/v1_legacy
V2_SNAPSHOT ?= snapshots/v2_current
DB_PATH     ?= artifacts/review.sqlite

.PHONY: build test fuzz-go review clean libfuzzer libfuzzer-run

build:
	$(GO) build ./...

test:
	$(GO) test ./...

# Native Go fuzzing of the truncation-tolerant parser (no C toolchain needed).
fuzz-go:
	$(GO) test -fuzz FuzzDecode -fuzztime 30s ./internal/parse/

# Run the review pipeline over the two versioned snapshots.
review: build
	$(GO) run ./cmd/lfi-review -v1 $(V1_SNAPSHOT) -v2 $(V2_SNAPSHOT) -db $(DB_PATH) -v

# Inspect the persisted evidence and the cross-snapshot review view.
query:
	$(GO) run ./cmd/lfi-query -db $(DB_PATH)

# Build the libFuzzer binary. The Go-generated main calls LLVMFuzzerRunDriver
# (see fuzz/libfuzzer/bridge.go). A linker script pulls fuzzer_no_main.a
# exactly once: Go forwards CGO_LDFLAGS twice, which would otherwise pull the
# archive twice and fail with duplicate sanitizer symbols.
libfuzzer:
	@test -x "$(CLANG)" || { echo "set CLANG_DIR to an extracted LLVM release"; exit 1; }
	@test -n "$(FUZZ_RT)" || { echo "libclang_rt.fuzzer_no_main.a not found under $(CLANG_DIR)"; exit 1; }
	mkdir -p bin fuzz/artifacts
	printf 'GROUP ( %s )\n' "$(FUZZ_RT)" > $(LD_SCRIPT)
	CC=$(CLANG) CGO_ENABLED=1 CGO_LDFLAGS="$(abspath $(LD_SCRIPT)) -lm" \
		$(GO) build -tags libfuzzer \
		-o bin/lfi-fuzz ./fuzz/libfuzzer

# Run libFuzzer against the seeded corpus. Findings land in fuzz/artifacts.
libfuzzer-run: libfuzzer
	mkdir -p fuzz/artifacts
	./bin/lfi-fuzz fuzz/corpus -artifact_prefix=fuzz/artifacts/ \
		-max_total_time=60 -print_final_stats=1

clean:
	rm -rf bin artifacts/review.sqlite artifacts/review.sqlite-* \
		fuzz/artifacts internal/parse/testdata/fuzz
