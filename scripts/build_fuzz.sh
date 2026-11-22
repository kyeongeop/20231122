#!/usr/bin/env bash
# Build the libFuzzer harness against the Go DNS validation pipeline.
# Requires: Go SDK and an LLVM/clang toolchain with compiler-rt (libFuzzer).
# Paths are overridable via GO / CLANG / LLVM_LIB env variables.
set -euo pipefail
cd "$(dirname "$0")/.."

GO=${GO:-go}
CLANG=${CLANG:-clang}

# When clang was extracted from .deb packages into a local prefix it needs
# its LLVM shared libraries on the loader path.
if [[ -n "${LLVM_LIB:-}" ]]; then
  export LD_LIBRARY_PATH="${LLVM_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
fi

"$GO" build -buildmode=c-shared -o fuzz/libdnsfuzz.so ./fuzz
"$CLANG" -fsanitize=fuzzer,address fuzz/fuzzer.c fuzz/libdnsfuzz.so -o fuzz/dnsfuzz
echo "built fuzz/dnsfuzz"
