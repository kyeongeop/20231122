#!/usr/bin/env bash
# Build the real libFuzzer target. GO and CLANG may be overridden.
set -euo pipefail
cd "$(dirname "$0")"

GO=${GO:-go}
CLANGXX=${CLANGXX:-clang++}

mkdir -p build
"$GO" build -buildmode=c-archive -o build/libcorpusprobe.a ./bridge
"$CLANGXX" -O1 -g -fsanitize=fuzzer,address \
  harness.cc build/libcorpusprobe.a -o build/corpus_fuzz \
  -lpthread -ldl -lm
echo "built fuzz/build/corpus_fuzz"
