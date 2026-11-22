#!/usr/bin/env bash
# Build the Go detector as a c-shared library and drive it with libFuzzer.
# The harness fuzzes the pure detection state machine, including snapshot
# round-trip equivalence between segmented and one-shot processing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GO_BIN="${GO:-go}"
CLANGXX_BIN="${CLANGXX:-clang++}"
RUNS="${RUNS:-20000}"
MAX_LEN="${MAX_LEN:-16384}"
BUILD_DIR="${BUILD_DIR:-build/libfuzzer}"
CORPUS_DIR="$BUILD_DIR/corpus"
ARTIFACT_DIR="$BUILD_DIR/artifacts"

mkdir -p "$BUILD_DIR" "$CORPUS_DIR" "$ARTIFACT_DIR"
cp -f fuzz/corpus/* "$CORPUS_DIR"/

CGO_ENABLED=1 "$GO_BIN" build -buildmode=c-shared \
  -o "$BUILD_DIR/librrfuzz.so" ./fuzz/export

"$CLANGXX_BIN" -std=c++17 -O1 -g -fsanitize=fuzzer \
  -I "$BUILD_DIR" fuzz/libfuzzer/harness.cc \
  -L "$BUILD_DIR" -lrrfuzz \
  -Wl,-rpath,"$BUILD_DIR" \
  -o "$BUILD_DIR/fuzz_replay"

exec "$BUILD_DIR/fuzz_replay" \
  -runs="$RUNS" \
  -max_len="$MAX_LEN" \
  -timeout=10 \
  -artifact_prefix="$ARTIFACT_DIR/" \
  -print_final_stats=1 \
  "$CORPUS_DIR"
