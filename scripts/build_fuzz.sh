#!/usr/bin/env bash
# Build the libFuzzer harness against the Go checker pipeline.
# Requires: Go SDK and an LLVM/clang toolchain (paths overridable via env).
set -euo pipefail
cd "$(dirname "$0")/.."

GO=${GO:-go}
CLANG=${CLANG:-clang}

"$GO" build -buildmode=c-shared -o fuzz/libwsfuzz.so ./fuzz
"$CLANG" -fsanitize=fuzzer,address fuzz/fuzzer.c fuzz/libwsfuzz.so -o fuzz/wsfuzz
echo "built fuzz/wsfuzz"
